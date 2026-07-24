// 见 doc.go 的包说明
//
// 本文件定义聚合后的 Status/Report 数据模型，把 health 接入 kernel.Module
// 生命周期，并实现 Report() 的唯一聚合逻辑
package health

import (
	"context"

	"github.com/nervus-os/nervud/internal/control"
	"github.com/nervus-os/nervud/internal/motiongate"
	"github.com/nervus-os/nervud/internal/safety"
	"github.com/nervus-os/nervud/internal/service"
)

// Status 是聚合后的整体健康档位——"现在这台机器一句话状态"的唯一权威
type Status uint8

const (
	// StatusHealthy Safety 处于 NORMAL 且没有任何组件处于熔断态
	StatusHealthy Status = iota
	// StatusDegraded Safety 处于 NORMAL，但至少一个非致命组件已熔断
	// （Vital 组件熔断会在 service.onCircuitBreak 里同步触发 Safety Trip，
	// 因此走到这一档时残留的必然是非 Vital 组件——不需要 health 自己重新
	// 判断 Criticality，Safety 的状态已经隐含了这个结论，见 deriveStatus）
	StatusDegraded
	// StatusFault Safety 不处于 NORMAL（已锁存/恢复中/等待 re-arm），
	// 或聚合器本身未正确装配（nil Observer，fail-closed）
	StatusFault
)

func (s Status) String() string {
	switch s {
	case StatusHealthy:
		return "HEALTHY"
	case StatusDegraded:
		return "DEGRADED"
	default:
		return "FAULT"
	}
}

// Report 是一次 Report() 调用的完整快照：整体判定 + 三个权威源的原始快照
//
// Safety/Control/Components 直接复用各自包已经导出的类型，不做二次投影——
// health 不比原始来源更懂这些字段的含义，转述一遍只会制造漂移的风险
type Report struct {
	Status     Status
	Safety     safety.Snapshot
	Control    control.Snapshot
	Components []service.Instance
}

// ControlObserver 是对 control.Module 的窄接口：读控制面一致快照
type ControlObserver interface {
	ControlSnapshot() control.Snapshot
}

// ServiceObserver 是对 service.Manager 的窄接口：枚举全部已知组件实例的只读快照
type ServiceObserver interface {
	Instances() []service.Instance
}

// Module 把 health 接入 kernel.Module 生命周期，并持有三个只读观察窄接口
//
// v1 的 Start/Stop 都是空操作：它不持有任何自己的状态，Report() 每次调用
// 现读三个权威源，没有需要启动的后台循环，也没有需要停机时收尾的东西
type Module struct {
	safety  safety.Observer // 复用 safety 自己定义的 Observer，不重新发明
	control ControlObserver
	service ServiceObserver
}

// New 构造 health 的 Module。三个观察者分别由 *safety.Module/*control.Module/
// *service.Manager 隐式满足（main.go 装配范式）
func New(safetyObs safety.Observer, controlObs ControlObserver, serviceObs ServiceObserver) *Module {
	return &Module{safety: safetyObs, control: controlObs, service: serviceObs}
}

func (m *Module) Name() string { return "health" }

// Start 无需要执行的初始化逻辑：Report() 现读现算，不需要预热任何状态
func (m *Module) Start(_ context.Context) error { return nil }

// Stop 纯只读聚合，没有需要释放的资源
func (m *Module) Stop(_ context.Context) error { return nil }

// Report 现读三个权威源并合成一份聚合快照。对未装配字段（nil）fail-safe：
// 缺失的观察者按"零值快照参与判定"处理，且 deriveStatus 的 fail-closed 规则
// 保证"看不到 Safety 状态"永远不会被误判成 Healthy
func (m *Module) Report() Report {
	if m == nil {
		return Report{Status: StatusFault}
	}

	var safetySnap safety.Snapshot
	if m.safety != nil {
		safetySnap = m.safety.SafetySnapshot()
	}
	var controlSnap control.Snapshot
	if m.control != nil {
		controlSnap = m.control.ControlSnapshot()
	}
	var comps []service.Instance
	if m.service != nil {
		comps = m.service.Instances()
	}

	return Report{
		Status:     deriveStatus(safetySnap, comps),
		Safety:     safetySnap,
		Control:    controlSnap,
		Components: comps,
	}
}

// deriveStatus 是 Status 判定的唯一实现：Safety 优先于组件熔断
//
// 未初始化/零值 safety.Snapshot 的 State 是 motiongate.StateInvalid，天然
// != StateNormal，落入 Fault 分支——与 motiongate 自己"零值 Gate 双重
// fail-closed"的既有约定一致，不需要 health 再加一层 nil 特判。
//
// 不读 Instance.Crit（pkgregistry.Criticality），也不需要 import
// pkgregistry：Vital 组件熔断已经在 service.onCircuitBreak 里同步调用
// m.safety.Trip()，所以本函数看到 Safety 仍是 NORMAL 时，能安全推出"当前
// 所有 StateFailed 组件都不是 Vital"，不需要自己重新判断 Criticality 等级
func deriveStatus(s safety.Snapshot, comps []service.Instance) Status {
	if s.State != motiongate.StateNormal {
		return StatusFault
	}
	// 按下标读字段，不整体拷贝元素：service.Instance 内嵌 sync.Once，
	// range 逐元素拷贝会被 go vet 判定为拷贝锁
	for i := range comps {
		if comps[i].State == service.StateFailed {
			return StatusDegraded
		}
	}
	return StatusHealthy
}
