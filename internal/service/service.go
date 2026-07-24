// Package service 管理 App / Service 组件的生命周期（应用层架构决策 §5）。
//
// 它是「装完的包能不能真正跑起来」的关键一环：pkgregistry 负责把包验证、裁决、
// 登记进 Registry，service.Manager 负责把 Registry 里 enabled 的组件经 authority
// →systemd 拉起成沙箱进程、监视其崩溃并按 criticality 分级处置，并维护一份
// unit→组件 的反查索引（byUnit）解锁 ipc.verifyComponent（§5.5）。
//
// 依赖方向：service → authority（起停进程）、pkgregistry（读 Registry）、
// audit。它【不】import safety，Vital 组件熔断经窄接口 SafetyEscalator 通知
// （由 main.go 用适配器接到 safety.Trip），避免把 safety 的 ReasonCode 语义
// 渗进本包。
package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// State 是一个组件实例的生命周期状态（应用层架构决策 §5.3）
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
	Unit        string
	Runtime     pkgregistry.Runtime
	Crit        pkgregistry.Criticality
	LaunchMode  pkgregistry.LaunchMode

	State  State
	Handle authority.ProcessHandle

	// crashes 是最近的崩溃时间戳（滑动窗口），用于「<10s 内 5 次 → 熔断」判定
	crashes []time.Time

	// stopCh 由 requestStop 关闭，通知本实例的 supervisor：这是【预期内】停止，
	// WaitProcess 返回后不要重启
	stopCh   chan struct{}
	stopOnce sync.Once
	// done 在 supervisor 完全退出（含停掉 unit）后关闭。ReloadPackage 升级时据此
	// 确认旧实例已彻底停掉，再起新版本，避免共享 unit 名的起/停竞态
	done chan struct{}
}

// snapshot 返回 Instance 的只读副本（不含内部 channel），供跨包返回
func (i *Instance) snapshot() Instance {
	return Instance{
		PackageID: i.PackageID, ComponentID: i.ComponentID, UID: i.UID, Unit: i.Unit,
		Runtime: i.Runtime, Crit: i.Crit, LaunchMode: i.LaunchMode,
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

// SafetyEscalator 在 Vital 组件熔断时被调用，触发 Safety 锁存（§5.4）。
// service 不 import safety——main.go 用适配器把 Trip() 接到
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
	safety SafetyEscalator
	aud    audit.Recorder
	log    *slog.Logger
	inv    *Invariants

	mu     sync.Mutex
	byKey  map[componentKey]*Instance
	byUnit map[string]*Instance // ← verifyComponent 的反查索引

	// ctx/cancel 控制全部 supervisor goroutine 的 WaitProcess 与退避等待；
	// Stop 时 cancel 让阻塞中的 WaitProcess 立刻返回
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// fatal 实现 kernel.FatalReporter 的接缝：容量 1。注意组件崩溃【绝不】写它——
	// §5.4 明确「服务崩溃不能带走内核」，崩溃只会重启/熔断/（Vital）升级 Safety，
	// 而非 kill nervud。它保留给「Manager 监视基础设施本身不可恢复」这类真·致命，
	// v1 尚无此路径，故该 channel 目前永不触发
	fatal chan error

	// backoffMin/backoffMax 是崩溃重启退避的上下界；生产用 restartBackoff* 常量，
	// 测试可调小以免熔断用例真的等十几秒
	backoffMin time.Duration
	backoffMax time.Duration

	stopped bool
}

// New 构造 Manager
func New(auth ProcessController, pkgs PackageLookup, safety SafetyEscalator, aud audit.Recorder, log *slog.Logger, inv *Invariants) *Manager {
	if inv == nil {
		inv = authority.DefaultInvariants()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		auth: auth, pkgs: pkgs, safety: safety, aud: aud, log: log, inv: inv,
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

// Start 拉起全部 enabled 且 always-on 的组件（§5.6：注册在 safety 之后、ipc 之前）
//
// 单个组件启动失败只记审计、不阻断整条启动——一个坏组件不该拖垮内核启动。真正
// 阻断启动的是装配级错误（如 auth/pkgs 为 nil），那在 New 之前就该暴露
func (m *Manager) Start(_ context.Context) error {
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
// 返回，最后 join 全部 supervisor（§5.6 关闭反序：ipc→service→safety）
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil
	}
	m.stopped = true
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

	// cancel 让阻塞中的 WaitProcess/退避等待立刻返回，然后 join
	m.cancel()
	m.wg.Wait()
	return nil
}

// LookupByUnit 按 systemd unit 名反查组件实例快照（解锁 ipc.verifyComponent，§5.5）
func (m *Manager) LookupByUnit(unit string) (Instance, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst, ok := m.byUnit[unit]
	if !ok {
		return Instance{}, false
	}
	return inst.snapshot(), true
}

// EnsureStarted 拉起一个 on-demand 组件（Resolve 到其 endpoint 时调用，§5.3）。
// 已在运行则幂等返回
func (m *Manager) EnsureStarted(_ context.Context, pkg, comp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := componentKey{pkg, comp}
	if inst, ok := m.byKey[key]; ok {
		if inst.State == StateRunning || inst.State == StateStarting {
			return nil // 幂等
		}
		if inst.State == StateDisabled {
			return fmt.Errorf("service: component %s/%s is disabled", pkg, comp)
		}
	}

	e, ok := m.pkgs.Lookup(pkg)
	if !ok {
		return fmt.Errorf("service: unknown package %q", pkg)
	}
	c, ok := e.Manifest.Component(comp)
	if !ok {
		return fmt.Errorf("service: package %q has no component %q", pkg, comp)
	}
	if e.ComponentDisabled(comp) {
		return fmt.Errorf("service: component %s/%s is disabled", pkg, comp)
	}
	m.startLocked(e, c)
	return nil
}

// ReloadPackage 在升级后把某 Package 的运行实例切换到新版本（应用层架构决策 §4.3）：
// 停掉全部旧实例并等它们彻底退出（unit 停稳），再用【当前 Registry 的新版本】重起
// always-on 组件。先停后起是必须的——组件 unit 名与版本无关，旧 unit 未停就起新版本
// 会在同一个 unit 名上发生起/停竞态（§P1 升级修复）
func (m *Manager) ReloadPackage(ctx context.Context, pkg string) error {
	// 1. 摘下并请求停掉该包全部旧实例
	m.mu.Lock()
	var olds []*Instance
	for key, inst := range m.byKey {
		if key.pkg == pkg {
			olds = append(olds, inst)
			m.requestStop(inst)
			delete(m.byKey, key)
			delete(m.byUnit, inst.Unit)
		}
	}
	m.mu.Unlock()

	// 2. 等旧 supervisor 彻底退出（它们自会 stopProc 停掉 unit）。不持 mu 等待，
	//    否则与 supervisor 的 setState/onStarted 争锁死锁
	for _, inst := range olds {
		select {
		case <-inst.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// 3. 用新版本重起 always-on 组件（on-demand/manual 等 Resolve/显式请求再拉起）
	e, ok := m.pkgs.Lookup(pkg)
	if !ok {
		return nil // 升级后又被卸载：无需重起
	}
	m.mu.Lock()
	for _, c := range e.Manifest.Components {
		if c.LaunchMode == pkgregistry.LaunchAlwaysOn && !e.ComponentDisabled(c.ID) {
			m.startLocked(e, c)
		}
	}
	m.mu.Unlock()
	return nil
}

// StopComponent 停止一个组件实例（不改变其 enabled 状态；SetEnabled 才动持久停用）
func (m *Manager) StopComponent(ctx context.Context, pkg, comp string) error {
	m.mu.Lock()
	inst, ok := m.byKey[componentKey{pkg, comp}]
	var h authority.ProcessHandle
	if ok {
		h = inst.Handle
	}
	m.mu.Unlock()
	if !ok {
		return nil // 未在运行，幂等
	}
	m.requestStop(inst)
	if h.Unit() != "" {
		return m.auth.StopProcess(ctx, authority.SubjectKernel(),
			authority.StopProcessRequest{Handle: h})
	}
	return nil
}
