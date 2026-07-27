// Package service 管理 App / Service 组件的生命周期。
//
// 它是装完的包能不能真正跑起来的关键一环：pkgregistry 负责把包验证、裁决、
// 登记进 Registry，service.Manager 负责把 Registry 里 enabled 的组件经 authority
// -> systemd 拉起成沙箱进程、监视其崩溃并按 criticality 分级处置，并维护一份
// unit -> 组件 的反查索引（byUnit）解锁 ipc.verifyComponent。
//
// 依赖方向：service -> authority（起停进程）、pkgregistry（读 Registry）、
// audit。它不import safety，Vital 组件熔断经窄接口 SafetyEscalator 通知
// （由 main.go 用适配器接到 safety.Trip），避免把 safety 的 ReasonCode 语义
// 渗进本包。
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// State 是一个组件实例的生命周期状态
type State uint8

const (
	StateStopped  State = iota // 未运行（初始/被停）
	StateStarting              // 正在拉起
	StateRunning               // 运行中
	StateStopping              // 正在停（intentional，崩溃监视据此不重启）
	StateFailed                // 熔断：耗尽重启预算，停止自动重启
	StateDisabled              // 被停用（SetEnabled(false)）
)

func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateFailed:
		return "failed"
	case StateDisabled:
		return "disabled"
	default:
		return "stopped"
	}
}

// componentKey 唯一标识一个组件实例（Package 内 Component 唯一）
type componentKey struct {
	pkg  string
	comp string
}

// Instance 是一个组件实例的运行期状态
//
// 只读快照经 LookupByUnit 返回给 ipc；内部可变字段（State/Handle/崩溃计数）由
// Manager 在持 mu 时读写，或由该实例自己的 supervisor goroutine 读写
type Instance struct {
	PackageID   string
	ComponentID string
	UID         uint32
	Generation  uint64
	Unit        string
	Type        pkgregistry.ComponentType
	Runtime     pkgregistry.Runtime
	Crit        pkgregistry.Criticality
	LaunchMode  pkgregistry.LaunchMode

	State  State
	Handle authority.ProcessHandle

	// crashes 是最近的崩溃时间戳（滑动窗口），用于<10s 内 5 次 -> 熔断判定
	crashes []time.Time

	// stopCh 由 requestStop 关闭，通知本实例的 supervisor：这是预期内停止，
	// WaitProcess 返回后不要重启
	stopCh   chan struct{}
	stopOnce sync.Once
	// done 在 supervisor 完全退出（含停掉 unit）后关闭。ReloadPackage 升级时据此
	// 确认旧实例已彻底停掉，再起新版本，避免共享 unit 名的起/停竞态
	done chan struct{}

	// sandboxRestartPending records that a runtime-permission projection must
	// restart this component after its old mount namespace is gone. It remains
	// set across a caller timeout so a retry can finish the same transition
	// instead of treating the stopped instance as unrelated. Protected by
	// Manager.mu.
	sandboxRestartPending bool
}

// ComponentIdentity is the lock-free projection used by IPC during handshake.
// Returning this value avoids copying Instance's internal sync.Once/channels
// across the package boundary.
type ComponentIdentity struct {
	PackageID   string
	ComponentID string
	UID         uint32
	Generation  uint64
	Type        pkgregistry.ComponentType
	State       State
}

// snapshot 返回 Instance 的只读副本（不含内部 channel），供跨包返回
func (i *Instance) snapshot() Instance {
	return Instance{
		PackageID: i.PackageID, ComponentID: i.ComponentID, UID: i.UID, Unit: i.Unit,
		Generation: i.Generation,
		Type:       i.Type, Runtime: i.Runtime, Crit: i.Crit, LaunchMode: i.LaunchMode,
		State: i.State, Handle: i.Handle,
	}
}

// ---- 窄接口依赖（消费者定义，具体类型隐式满足）---------------------------

// ProcessController 是对 authority.Gate 的窄接口：起/停/等一个沙箱进程
type ProcessController interface {
	StartSandboxedProcess(ctx context.Context, subj authority.Subject, req authority.StartSandboxedProcessRequest) (authority.ProcessHandle, error)
	StopProcess(ctx context.Context, subj authority.Subject, req authority.StopProcessRequest) error
	WaitProcess(ctx context.Context, h authority.ProcessHandle) (authority.ExitInfo, error)
}

// PackageLookup 是对 pkgregistry.Registry 的窄接口：读已装包
type PackageLookup interface {
	Lookup(id string) (pkgregistry.Entry, bool)
	List() []pkgregistry.Entry
}

// PermissionLookup is the runtime permission view used when projecting
// user-consent grants into a process sandbox. The package Entry still supplies
// install-time eligibility; both checks must pass before a shared writable path
// is mounted.
type PermissionLookup interface {
	Allowed(packageID, permission string) bool
}

// SafetyEscalator 在 Vital 组件熔断时被调用，触发 Safety 锁存。
// service 不 import safety - main.go 用适配器把 Trip 接到
// safety.Trip(ReasonSupervisorEscalation)
type SafetyEscalator interface {
	Trip()
}

// Invariants 是 service 需要的路径/UID 不变量（用 authority.Invariants）
type Invariants = authority.Invariants

// Manager 是组件生命周期管理器（kernel.Module）
type Manager struct {
	auth   ProcessController
	pkgs   PackageLookup
	perms  PermissionLookup
	safety SafetyEscalator
	aud    audit.Recorder
	log    *slog.Logger
	inv    *Invariants

	mu     sync.Mutex
	byKey  map[componentKey]*Instance
	byUnit map[string]*Instance // <- verifyComponent 的反查索引

	// ctx/cancel 控制全部 supervisor goroutine 的 WaitProcess 与退避等待；
	// Stop 时 cancel 让阻塞中的 WaitProcess 立刻返回
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// fatal 实现 kernel.FatalReporter 的接缝：容量 1。注意组件崩溃绝不写它 -
	// 明确服务崩溃不能带走内核，崩溃只会重启/熔断/（Vital）升级 Safety，
	// 而非 kill nervud。它保留给 Manager 监视基础设施本身不可恢复这类真正致命、
	// v1 尚无此路径，故该 channel 目前永不触发
	fatal chan error

	// backoffMin/backoffMax 是崩溃重启退避的上下界；生产用 restartBackoff* 常量，
	// 测试可调小以免熔断用例真的等十几秒
	backoffMin time.Duration
	backoffMax time.Duration

	stopped      bool
	stopComplete bool

	// stagingPkgID/stagingRoot 是「装包服务额外可写 staging 根」这条例外。
	// 经 GrantStagingAccess 注入，不注入则为空、无任何组件拿到额外可写路径。
	// 装配期一次性写入，Start 之后只读，故不受 mu 保护。
	stagingPkgID string
	stagingRoot  string

	// sandboxReloadMu serializes package restarts caused by upgrades and runtime
	// permission projection. It is deliberately independent from mu: both paths
	// wait for supervisor goroutines, which briefly need mu while exiting.
	sandboxReloadMu sync.Mutex
}

// GrantStagingAccess 让 packageID 的组件对 stagingRoot 可写。
//
// 这是【唯一】一条「某个包比别人多一个可写目录」的例外，因此做成显式注入而不是
// 从别处推断：装包服务要在 nervud 分配的 staging 目录里解包，而 ProtectSystem=strict
// 让整个文件系统只读。谁有这个例外必须在装配处一眼可见（main.go），不该藏在
// 某个按 package_id 猜测的条件里。
//
// 必须在 Start 之前调用。
func (m *Manager) GrantStagingAccess(packageID, stagingRoot string) {
	m.stagingPkgID = packageID
	m.stagingRoot = stagingRoot
}

// New 构造 Manager
func New(
	auth ProcessController,
	pkgs PackageLookup,
	perms PermissionLookup,
	safety SafetyEscalator,
	aud audit.Recorder,
	log *slog.Logger,
	inv *Invariants,
) *Manager {
	if inv == nil {
		inv = authority.DefaultInvariants()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		auth: auth, pkgs: pkgs, perms: perms, safety: safety, aud: aud, log: log, inv: inv,
		byKey:  make(map[componentKey]*Instance),
		byUnit: make(map[string]*Instance),
		ctx:    ctx, cancel: cancel,
		fatal:      make(chan error, 1),
		backoffMin: restartBackoffMin,
		backoffMax: restartBackoffMax,
	}
}

func (m *Manager) Name() string { return "service" }

// Fatal 实现 kernel.FatalReporter：supervisor 的致命错误经此上报，触发内核反序关闭
func (m *Manager) Fatal() <-chan error { return m.fatal }

// Start 拉起全部 enabled 且 always-on 的组件（注册在 safety 之后、ipc 之前）
//
// 单个组件启动失败只记审计、不阻断整条启动 - 一个坏组件不该拖垮内核启动。真正
// 阻断启动的是装配级错误（如 auth/pkgs 为 nil），那在 New 之前就该暴露
func (m *Manager) Start(_ context.Context) error {
	m.sandboxReloadMu.Lock()
	defer m.sandboxReloadMu.Unlock()

	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return ErrManagerStopped
	}
	m.mu.Unlock()

	for _, e := range m.pkgs.List() {
		for _, c := range e.Manifest.Components {
			if c.LaunchMode != pkgregistry.LaunchAlwaysOn {
				continue // on-demand 等 EnsureStarted；manual 等显式请求
			}
			if e.ComponentDisabled(c.ID) {
				continue
			}
			m.mu.Lock()
			m.startLocked(e, c)
			m.mu.Unlock()
		}
	}
	return nil
}

// Stop 反序停全部实例：先请求每个实例停（intentional），再 cancel 让 WaitProcess
// 返回，最后 join 全部 supervisor（ 关闭反序：ipc -> service -> safety）
func (m *Manager) Stop(ctx context.Context) error {
	// Publish the terminal state and cancel supervisors before waiting for a
	// package reload. A reload may itself be waiting for one of those
	// supervisors, so taking sandboxReloadMu first would deadlock shutdown.
	m.mu.Lock()
	m.stopped = true
	m.mu.Unlock()
	m.cancel()

	m.sandboxReloadMu.Lock()
	defer m.sandboxReloadMu.Unlock()

	m.mu.Lock()
	if m.stopComplete {
		m.mu.Unlock()
		return nil
	}
	insts := make([]*Instance, 0, len(m.byKey))
	for _, inst := range m.byKey {
		insts = append(insts, inst)
	}
	m.mu.Unlock()

	// 请求每个实例停 + 主动 StopProcess（systemd StopUnit）。用传入的 ctx（内核关停
	// 预算），读 Handle 走 mu 快照避免与 supervisor 的写竞态
	for _, inst := range insts {
		m.requestStop(inst)
		m.mu.Lock()
		h := inst.Handle
		unit := inst.Unit
		m.mu.Unlock()
		if h.Unit() != "" {
			if err := m.auth.StopProcess(ctx, authority.SubjectKernel(),
				authority.StopProcessRequest{Handle: h}); err != nil {
				m.log.Warn("service: StopProcess failed during shutdown", "unit", unit, "err", err)
			}
		}
	}

	// cancel 已在等待 lifecycle 锁前发出；这里 join 保证没有 supervisor 被漏掉。
	m.wg.Wait()
	m.mu.Lock()
	m.stopComplete = true
	m.mu.Unlock()
	return nil
}

// LookupByUnit 按 systemd unit 名反查组件实例快照，供 IPC 核对 Component 身份
func (m *Manager) LookupByUnit(unit string) (Instance, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.byUnit[unit]
	if !ok {
		return Instance{}, false
	}
	return inst.snapshot(), true
}

// LookupComponentByUnit returns only the kernel facts needed to authenticate an
// IPC component. It deliberately excludes supervisor synchronization state.
func (m *Manager) LookupComponentByUnit(unit string) (ComponentIdentity, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.byUnit[unit]
	if !ok {
		return ComponentIdentity{}, false
	}
	return ComponentIdentity{
		PackageID:   inst.PackageID,
		ComponentID: inst.ComponentID,
		UID:         inst.UID,
		Generation:  inst.Generation,
		Type:        inst.Type,
		State:       inst.State,
	}, true
}

// 启动失败的哨兵错误。
//
// 用哨兵而不是只有错误字符串：调用方（ipc 的 LaunchComponent 接线）要把失败
// 原因映射成 wire 上的 typed reason，好让 Launcher 区分「没这个应用」和
// 「应用被停用了」——后者应当提示用户去设置里启用，前者不该。
// 靠匹配错误字符串做这件事，会在有人改一句措辞时静默失效。
var (
	// ErrUnknownPackage 目标 Package 未安装
	ErrUnknownPackage = errors.New("service: unknown package")
	// ErrUnknownComponent Package 存在但没有该 Component
	ErrUnknownComponent = errors.New("service: unknown component")
	// ErrComponentDisabled 组件被停用（nervusctl disable 或 manifest 声明）
	ErrComponentDisabled = errors.New("service: component disabled")
	// ErrManagerStopped 表示 service 生命周期已经进入终态，不能再创建 supervisor。
	ErrManagerStopped = errors.New("service: manager stopped")
	// ErrComponentFailed 组件已耗尽重启预算被熔断。
	//
	// 【EnsureStarted 目前不会返回它】：熔断只停止自动重启，显式请求仍允许
	// 重试（见 EnsureStarted 里的说明）。保留它是因为 wire 上
	// LAUNCH_COMPONENT_REASON_COMPONENT_FAILED 这个 reason 已经冻结，
	// 将来若改成"熔断后拒绝显式拉起"，映射不用再动。
	ErrComponentFailed = errors.New("service: component failed (restart budget exhausted)")
)

// IsRunning 报告某组件此刻是否在跑（含正在启动）。
//
// 供 LaunchComponent 回答 already_running。它是一个瞬时快照，返回后状态随时
// 可能变——调用方不该用它做「先查再启动」的判断，那是 TOCTOU；EnsureStarted
// 本身就幂等，直接调即可，这个值只用于告知。
func (m *Manager) IsRunning(pkg, comp string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.byKey[componentKey{pkg, comp}]
	return ok && (inst.State == StateRunning || inst.State == StateStarting)
}

// EnsureStarted 拉起一个组件；已在运行则幂等返回。
//
// 两个调用方：endpoint.Resolve 解析到 on-demand 提供者时，以及 ipc 的
// LaunchComponent（Launcher 点开一个 App）。
func (m *Manager) EnsureStarted(_ context.Context, pkg, comp string) error {
	m.sandboxReloadMu.Lock()
	defer m.sandboxReloadMu.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return ErrManagerStopped
	}

	key := componentKey{pkg, comp}
	if inst, ok := m.byKey[key]; ok {
		if inst.State == StateRunning || inst.State == StateStarting {
			return nil // 幂等
		}
		if inst.State == StateDisabled {
			return fmt.Errorf("%w: %s/%s", ErrComponentDisabled, pkg, comp)
		}
		// StateFailed（熔断）【不】在这里拦：重启预算挡的是"自动无限重启"，
		// 而 EnsureStarted 的两个调用方都是显式动作——用户点图标，或有人
		// Resolve 了这个接口。人主动重试一次该被允许，否则一个组件崩过五次
		// 之后就永远打不开了，只能重启整机。见 TestEnsureStarted_RestartsAfterCircuitBreak
	}

	e, ok := m.pkgs.Lookup(pkg)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownPackage, pkg)
	}
	c, ok := e.Manifest.Component(comp)
	if !ok {
		return fmt.Errorf("%w: %q has no component %q", ErrUnknownComponent, pkg, comp)
	}
	if e.ComponentDisabled(comp) {
		return fmt.Errorf("%w: %s/%s", ErrComponentDisabled, pkg, comp)
	}
	m.startLocked(e, c)
	return nil
}

// ReloadPackage 在升级后把某 Package 的运行实例切换到新版本：
// 停掉全部旧实例并等它们彻底退出（unit 停稳），再用当前 Registry 的新版本重起
// always-on 组件。先停后起是必须的 - 组件 unit 名与版本无关，旧 unit 未停就起新版本
// 会在同一个 unit 名上发生起/停竞态（ 升级修复）
func (m *Manager) ReloadPackage(ctx context.Context, pkg string) error {
	m.sandboxReloadMu.Lock()
	defer m.sandboxReloadMu.Unlock()

	// 1. 请求停掉该包全部旧实例。映射必须保留到全部 done；若调用方超时，
	// EnsureStarted 会继续看到旧实例而不会在同名 unit 上抢跑。
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return ErrManagerStopped
	}
	var olds []*Instance
	for key, inst := range m.byKey {
		if key.pkg == pkg {
			olds = append(olds, inst)
			m.requestStop(inst)
		}
	}
	m.mu.Unlock()

	// 2. 等旧 supervisor 彻底退出（它们自会 stopProc 停掉 unit）。不持 mu 等待，
	//  否则与 supervisor 的 setState/onStarted 争锁死锁
	for _, inst := range olds {
		select {
		case <-inst.done:
		case <-ctx.Done():
			return ctx.Err()
		case <-m.ctx.Done():
			return ErrManagerStopped
		}
	}

	// 3. 只有全部旧 supervisor 退出后才摘映射并用新版本重起 always-on 组件
	// （on-demand/manual 等 Resolve/显式请求再拉起）。
	e, ok := m.pkgs.Lookup(pkg)
	m.mu.Lock()
	m.detachInstancesLocked(olds)
	if !ok {
		m.mu.Unlock()
		return nil // 升级后又被卸载：无需重起
	}
	if m.stopped {
		m.mu.Unlock()
		return ErrManagerStopped
	}
	for _, c := range e.Manifest.Components {
		if c.LaunchMode == pkgregistry.LaunchAlwaysOn && !e.ComponentDisabled(c.ID) {
			m.startLocked(e, c)
		}
	}
	m.mu.Unlock()
	return nil
}

// RevokeInstallGrant records an immediate stop intent for processes whose
// install-time sandbox authority was removed. It intentionally performs no
// package lookup, systemd call, or wait because permission.Registry.Replace may
// invoke it while pkgregistry holds its transaction mutex. Each supervisor owns
// the eventual StopProcess call, including the window where process startup has
// not returned a handle yet.
func (m *Manager) RevokeInstallGrant(packageID, permission string) {
	if permission != permStorageUser {
		return
	}
	m.mu.Lock()
	for key, inst := range m.byKey {
		if key.pkg == packageID && instanceMayBeRunning(inst.State) {
			m.requestStop(inst)
		}
	}
	m.mu.Unlock()
}

// ProjectRuntimePermission rebuilds active component sandboxes after a
// USER_CONSENT decision changes. Runtime state has already been committed by
// permission.Registry before this method is called, so every replacement
// process observes the new Allowed result while building ReadWritePaths.
//
// This hook is intentionally not used by permission.Registry.Replace. Package
// projection can run while pkgregistry holds its transaction mutex; waiting for
// supervisors or looking the package up from that callback would introduce a
// lock inversion and could restart a package during rollback or uninstall.
func (m *Manager) ProjectRuntimePermission(packageID, permission string, allowed bool) error {
	if permission != permStorageUser {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), startStopTimeout)
	defer cancel()
	err := m.restartActivePackage(ctx, packageID)
	if m.aud != nil {
		m.aud.Record(context.Background(), audit.Event{
			Action:  "service.ProjectRuntimePermission",
			Subject: packageID,
			Denied:  err != nil,
			Err:     err,
			Detail:  fmt.Sprintf("%s allowed=%t", permission, allowed),
		})
	}
	return err
}

// restartActivePackage stops every live component of one package, waits until
// its transient unit (and therefore its mount namespace) is gone, then starts
// the same component set against the current package and permission snapshots.
func (m *Manager) restartActivePackage(ctx context.Context, packageID string) error {
	m.sandboxReloadMu.Lock()
	defer m.sandboxReloadMu.Unlock()

	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return ErrManagerStopped
	}
	olds := make([]*Instance, 0)
	componentIDs := make([]string, 0)
	for key, inst := range m.byKey {
		if key.pkg != packageID ||
			(!instanceMayBeRunning(inst.State) && !inst.sandboxRestartPending) {
			continue
		}
		inst.sandboxRestartPending = true
		olds = append(olds, inst)
		componentIDs = append(componentIDs, key.comp)
		m.requestStop(inst)
	}
	m.mu.Unlock()

	for _, inst := range olds {
		select {
		case <-inst.done:
		case <-ctx.Done():
			return fmt.Errorf("service: project runtime permission for %q: %w", packageID, ctx.Err())
		case <-m.ctx.Done():
			return fmt.Errorf("service: project runtime permission for %q: %w", packageID, ErrManagerStopped)
		}
	}
	if len(componentIDs) == 0 {
		return nil
	}

	e, ok := m.pkgs.Lookup(packageID)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detachInstancesLocked(olds)
	if !ok {
		return nil
	}
	if m.stopped {
		return ErrManagerStopped
	}
	for _, componentID := range componentIDs {
		component, exists := e.Manifest.Component(componentID)
		if !exists || e.ComponentDisabled(componentID) {
			continue
		}
		m.startLocked(e, component)
	}
	return nil
}

func instanceMayBeRunning(state State) bool {
	return state == StateStarting || state == StateRunning || state == StateStopping
}

// detachInstancesLocked removes only the exact completed instances supplied by
// the caller. The identity check makes this safe against future code that may
// install a replacement between collection and cleanup. Caller must hold m.mu.
func (m *Manager) detachInstancesLocked(instances []*Instance) {
	for _, inst := range instances {
		key := componentKey{pkg: inst.PackageID, comp: inst.ComponentID}
		if m.byKey[key] == inst {
			delete(m.byKey, key)
		}
		if m.byUnit[inst.Unit] == inst {
			delete(m.byUnit, inst.Unit)
		}
		inst.sandboxRestartPending = false
	}
}

// StopComponent 停止一个组件实例（不改变其 enabled 状态；SetEnabled 才动持久停用）
func (m *Manager) StopComponent(ctx context.Context, pkg, comp string) error {
	m.sandboxReloadMu.Lock()
	defer m.sandboxReloadMu.Unlock()

	m.mu.Lock()
	inst, ok := m.byKey[componentKey{pkg, comp}]
	var h authority.ProcessHandle
	if ok {
		// An explicit lifecycle stop (disable/uninstall) supersedes a pending
		// permission-driven sandbox restart.
		inst.sandboxRestartPending = false
		m.requestStop(inst)
		h = inst.Handle
	}
	m.mu.Unlock()
	if !ok {
		return nil // 未在运行，幂等
	}
	var stopErr error
	if h.Unit() != "" {
		stopErr = m.auth.StopProcess(ctx, authority.SubjectKernel(),
			authority.StopProcessRequest{Handle: h})
	}
	select {
	case <-inst.done:
		return stopErr
	case <-ctx.Done():
		if stopErr != nil {
			return errors.Join(stopErr, ctx.Err())
		}
		return ctx.Err()
	}
}
