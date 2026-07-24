// 本文件把 endpoint 接入 kernel.Module 生命周期，并持有 Register/Resolve/Route
// 共用的窄接口依赖与内部状态操作（设计方案 §2/§7）
package endpoint

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// v1 [REWRITE-v1] 固定的唯一合法 Resource 选择器与句柄（设计方案 §6.3）。
// internal/resource 落地后这里要改成真正查 Resource Registry
const (
	resourceTypeMotionBase = "nervus.resource.motion.base"
	resourceRoleMain       = "main"
	resourceHandleBaseMain = "base.main"
)

// perm.service.register(.private) 的权限 ID 必须与 permission.DefaultCatalog
// 中登记的一致（应用层架构决策 §6.5）。不在这里 import permission 只为两个
// 字符串常量，避免额外耦合
const (
	permServiceRegister        = "perm.service.register"
	permServiceRegisterPrivate = "perm.service.register.private"
)

// onDemandStartTimeout 是等待 on-demand 组件完成启动并 RegisterEndpoint 的
// 上限（设计方案 §5.2 第 6 步："有界超时（如 3s）"）
const onDemandStartTimeout = 3 * time.Second

// 诊断/审计用哨兵错误
var (
	errExplicitComponent = errors.New("endpoint: explicit_component is not supported in v1")
	errResourceNotFound  = errors.New("endpoint: no caller-visible resource matches selector")
	errVersionMismatch   = errors.New("endpoint: no interface version in requested range")
	errPermissionDenied  = errors.New("endpoint: package lacks required permission")
	errInterfaceNotFound = errors.New("endpoint: interface not visible to caller")
	errAmbiguous         = errors.New("endpoint: interface resolves to more than one candidate")
	errOnDemandTimeout   = errors.New("endpoint: timed out waiting for on-demand component to register")
)

// ---- 窄接口依赖（消费者定义，具体类型隐式满足，设计方案 §2）-----------------

// PackageLookup 是对 pkgregistry.Registry 的窄接口：读已装包
//
// 照抄 service.PackageLookup 的同名接口，不重新发明
type PackageLookup interface {
	Lookup(id string) (pkgregistry.Entry, bool)
	List() []pkgregistry.Entry
}

// PermissionChecker 查询某个 Package 是否已被授予某项 permission
//
// 接口定义与 ipc.PermissionChecker 完全一致，endpoint 和 ipc 各自持有一份到
// *permission.Registry 的窄引用
type PermissionChecker interface {
	Allowed(packageID, permission string) bool
}

// ComponentStarter 拉起一个 on-demand 组件（Resolve 解析到它时调用）
//
// service.Manager 已经预留了这个方法，接口在这里（消费者）定义
type ComponentStarter interface {
	EnsureStarted(ctx context.Context, pkg, comp string) error
}

// Module 是 endpoint 的 kernel.Module 实现，持有 Register/Resolve/Route 的
// 全部运行期状态
//
// v1 的 Start/Stop 基本是空操作：它不持有自己的 RT Lane 或后台循环，全部状态
// 都挂在每条 IPC 连接的生命周期上，随连接创建/销毁（设计方案 §2）
type Module struct {
	pkgs    PackageLookup
	perm    PermissionChecker
	starter ComponentStarter
	aud     audit.Recorder
	log     *slog.Logger
	catalog InterfaceCatalog

	mu sync.Mutex

	byConn      map[ConnHandle]*connState
	byInterface map[string][]*serviceRegistration

	// pendingStarts 是 on-demand 拉起等待队列：Resolve 在 EnsureStarted 之后
	// 挂一个 channel，RegisterEndpoint 到达时关闭全部等待者对应 channel 唤醒
	pendingStarts map[componentKey][]chan struct{}

	// generations 记录每个 (pkg,comp,interface) 三元组已经历过的注册次数，
	// 供 serviceRegistration.generation 使用（设计方案 §4）
	generations map[registrationKey]uint64
}

// New 构造 endpoint 的 Module
//
// 窄接口注入（main.go 的装配范式）：pkgs/perm/starter 分别由 *pkgregistry.Registry
// /*permission.Registry/*service.Manager 隐式满足
func New(pkgs PackageLookup, perm PermissionChecker, starter ComponentStarter, aud audit.Recorder, log *slog.Logger) *Module {
	return &Module{
		pkgs: pkgs, perm: perm, starter: starter, aud: aud, log: log,
		catalog:       DefaultInterfaceCatalog(),
		byConn:        make(map[ConnHandle]*connState),
		byInterface:   make(map[string][]*serviceRegistration),
		pendingStarts: make(map[componentKey][]chan struct{}),
		generations:   make(map[registrationKey]uint64),
	}
}

func (m *Module) Name() string { return "endpoint" }

// Start 无后台循环需要起——全部状态挂在连接生命周期上（设计方案 §2）
func (m *Module) Start(context.Context) error { return nil }

// Stop 只做一次日志层面的"还有 N 个存活 binding"诊断输出（设计方案 §2）
func (m *Module) Stop(context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	var alive int
	for _, cs := range m.byConn {
		alive += len(cs.bindings)
	}
	m.mu.Unlock()

	if alive > 0 && m.log != nil {
		m.log.Info("endpoint: stopping with live bindings", "count", alive)
	}
	return nil
}

// audit 记一条 Register/Resolve/Unregister 审计事件
func (m *Module) audit(caller identity.Caller, action string, denied bool, err error, detail string) {
	if m.aud == nil {
		return
	}
	m.aud.Record(context.Background(), audit.Event{
		Action: action, Subject: caller.String(), Denied: denied, Err: err, Detail: detail,
	})
}

// connStateLocked 取或建某条连接的状态。调用方必须持有 m.mu
func (m *Module) connStateLocked(conn ConnHandle) *connState {
	cs, ok := m.byConn[conn]
	if !ok {
		cs = newConnState()
		m.byConn[conn] = cs
	}
	return cs
}

// removeFromInterfaceIndexLocked 把 reg 从 byInterface 索引摘掉。调用方必须
// 持有 m.mu。reg.live 由调用方另行置为 false——两者一起做才是一次完整的失效
func (m *Module) removeFromInterfaceIndexLocked(reg *serviceRegistration) {
	list := m.byInterface[reg.interfaceID]
	for i, r := range list {
		if r == reg {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(m.byInterface, reg.interfaceID)
		return
	}
	m.byInterface[reg.interfaceID] = list
}

// visibleCandidatesLocked 返回 byInterface[interfaceID] 中对 callerPkg 可见的
// registration：跨包只看 VisibilityPublic，同包再加 VisibilityPackage
// （设计方案 §5.2 第 3 步）。调用方必须持有 m.mu
func (m *Module) visibleCandidatesLocked(callerPkg, interfaceID string) []*serviceRegistration {
	var out []*serviceRegistration
	for _, reg := range m.byInterface[interfaceID] {
		if reg.packageID == callerPkg || reg.visibility == pkgregistry.VisibilityPublic {
			out = append(out, reg)
		}
	}
	return out
}

// findOnDemandCandidate 在已装包里找哪个 (pkg, comp) 的 manifest 声明了
// Exports 含 interfaceID 且对 callerPkg 可见（设计方案 §5.2 第 6 步）
//
// 不持有 m.mu：pkgs.List() 是 pkgregistry 自己的原子读，不需要 endpoint 的锁
func (m *Module) findOnDemandCandidate(callerPkg, interfaceID string) (pkg, comp string, found bool) {
	for _, e := range m.pkgs.List() {
		for _, c := range e.Manifest.Components {
			if e.ComponentDisabled(c.ID) {
				continue
			}
			for _, exp := range c.Exports {
				if exp.Interface != interfaceID {
					continue
				}
				if exp.Visibility == pkgregistry.VisibilityPublic || e.Manifest.PackageID == callerPkg {
					return e.Manifest.PackageID, c.ID, true
				}
			}
		}
	}
	return "", "", false
}

// tryOnDemandStart 拉起一个 on-demand 组件并等待它完成 RegisterEndpoint
//
// 等待 channel 必须在调用 EnsureStarted 之前登记，否则组件启动得足够快时，
// RegisterEndpoint 的广播可能发生在我们登记等待者之前，永远等不到唤醒
// （设计方案 §5.2 第 6 步）
func (m *Module) tryOnDemandStart(pkg, comp string) (started bool, err error) {
	key := componentKey{pkg: pkg, comp: comp}
	ch := make(chan struct{})

	m.mu.Lock()
	m.pendingStarts[key] = append(m.pendingStarts[key], ch)
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), onDemandStartTimeout)
	defer cancel()

	if serr := m.starter.EnsureStarted(ctx, pkg, comp); serr != nil {
		m.mu.Lock()
		m.removeWaiterLocked(key, ch)
		m.mu.Unlock()
		return false, serr
	}

	select {
	case <-ch:
		return true, nil
	case <-time.After(onDemandStartTimeout):
		m.mu.Lock()
		m.removeWaiterLocked(key, ch)
		m.mu.Unlock()
		return false, nil
	}
}

// removeWaiterLocked 从等待队列摘掉一个超时放弃的等待者。调用方必须持有 m.mu
func (m *Module) removeWaiterLocked(key componentKey, ch chan struct{}) {
	waiters := m.pendingStarts[key]
	for i, w := range waiters {
		if w == ch {
			waiters = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(waiters) == 0 {
		delete(m.pendingStarts, key)
		return
	}
	m.pendingStarts[key] = waiters
}
