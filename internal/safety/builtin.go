// 本文件把 Safety 的观察与恢复能力包成一个【内建 endpoint】的 handler，
// 供 nervud 在装配期注册（endpoint.RegisterBuiltin）。
//
// # 为什么在 safety 包里而不是 main.go
//
// 这里要做 motiongate.State → wire TopState、StopPhase → wire StopPhase 的
// 翻译，而这两个枚举的语义归 safety 所有。放进 main.go 会让装配代码承担
// 语义映射，而那正是最容易在加一个新状态时被漏掉的地方。
//
// # 它不提供 Trip
//
// 软件急停由别的路径触发（Vital 组件熔断、deadman 超时、Provider 上报故障）。
// 把「让机器停下来」做成一个可被任意 App 调的 RPC，会让一次误调用变成一次
// 生产事故——而急停本来就该由物理按钮与内核监督链兜底，不该依赖一次网络往返。
package safety

import (
	"context"

	"google.golang.org/protobuf/proto"

	safetyv1 "github.com/nervus-os/nervus-ipc/protocol/interface/safetyv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/motiongate"
)

// BuiltinInterfaceID 是本内建接口的 ID，必须与
// nervus-ipc 的 safety_control.proto 一致。
const BuiltinInterfaceID = "nervus.interface.safety.control"

// method_id 取自 proto 生成的枚举，不在本地重抄常量——抄一份会悄悄过期，
// 而过期的后果是调用被路由到错误的方法。
var (
	methodGetState        = uint32(safetyv1.SafetyControlMethod_SAFETY_CONTROL_METHOD_GET_STATE)
	methodRearm           = uint32(safetyv1.SafetyControlMethod_SAFETY_CONTROL_METHOD_REARM)
	methodRequestRecovery = uint32(safetyv1.SafetyControlMethod_SAFETY_CONTROL_METHOD_REQUEST_RECOVERY)
)

// BuiltinHandler 返回可直接交给 endpoint.RegisterBuiltin 的处理函数。
//
// The structured call/result shape keeps builtins on the same method gate as
// external Providers and leaves room for connection-scoped kernel services.
func (m *Module) BuiltinHandler() endpoint.BuiltinHandler {
	return func(call endpoint.BuiltinCall) endpoint.BuiltinResult {
		var payload []byte
		var code ipcv1.StatusCode
		switch call.MethodID {
		case methodGetState:
			payload, code = m.handleGetState()
		case methodRearm:
			payload, code = m.handleRearm(call.Caller)
		case methodRequestRecovery:
			payload, code = m.handleRequestRecovery(call.Caller)
		default:
			// fail closed：没实现的方法就是不存在，绝不静默成功——
			// 静默成功会让调用方以为 re-arm 生效了。
			code = ipcv1.StatusCode_STATUS_CODE_NOT_FOUND
		}
		return endpoint.BuiltinResult{Payload: payload, Code: code}
	}
}

func (m *Module) handleGetState() ([]byte, ipcv1.StatusCode) {
	snap := m.SafetySnapshot()
	out, err := proto.Marshal(&safetyv1.SafetyState{
		State:       topStateToWire(snap.State),
		MotionEpoch: snap.Epoch,
		StopPhase:   stopPhaseToWire(snap.StopPhase),
	})
	if err != nil {
		return nil, ipcv1.StatusCode_STATUS_CODE_INTERNAL
	}
	return out, ipcv1.StatusCode_STATUS_CODE_OK
}

func (m *Module) handleRearm(caller identity.Caller) ([]byte, ipcv1.StatusCode) {
	// Rearm 内部只复核不可绕过的硬前置（停止进度是否落定），策略在服务侧。
	if m.Rearm() {
		m.recordBuiltin(caller, "safety.Rearm", true)
		return nil, ipcv1.StatusCode_STATUS_CODE_OK
	}
	m.recordBuiltin(caller, "safety.Rearm", false)

	// 失败原因要可区分：调用方看到 STOP_NOT_SETTLED 应当【等待重试】，
	// 看到 WRONG_STATE 应当【停止尝试】。压成同一个码会让恢复 UI 要么无谓
	// 放弃，要么在一个永远不会成功的状态上死循环。
	return rearmFailureDetail(m.SafetySnapshot())
}

func (m *Module) handleRequestRecovery(caller identity.Caller) ([]byte, ipcv1.StatusCode) {
	if m.RequestRecovery() {
		m.recordBuiltin(caller, "safety.RequestRecovery", true)
		return nil, ipcv1.StatusCode_STATUS_CODE_OK
	}
	m.recordBuiltin(caller, "safety.RequestRecovery", false)
	return withDetail(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
		safetyv1.SafetyControlReason_SAFETY_CONTROL_REASON_WRONG_STATE)
}

// rearmFailureDetail 按当前快照判断 re-arm 失败的可区分原因。
func rearmFailureDetail(snap Snapshot) ([]byte, ipcv1.StatusCode) {
	if snap.State != motiongate.StateRearmRequired {
		// 压根不在 REARM_REQUIRED：再试多少次都一样
		return withDetail(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			safetyv1.SafetyControlReason_SAFETY_CONTROL_REASON_WRONG_STATE)
	}
	// 状态对但被拒 = 停止进度还没落定，等一会儿有戏
	return withDetail(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
		safetyv1.SafetyControlReason_SAFETY_CONTROL_REASON_STOP_NOT_SETTLED)
}

func withDetail(code ipcv1.StatusCode, reason safetyv1.SafetyControlReason) ([]byte, ipcv1.StatusCode) {
	// detail 走 error_detail 而不是 payload：失败的 Response 用的是 Failure
	// 分支，payload 那一路根本不会被读到。这里返回 nil payload，detail 由
	// ipc 侧从 code 构造——v1 的内建路径尚未透传 typed detail，见下方 TODO。
	//
	// TODO(builtin-detail)：BuiltinHandler 的签名只能返回 (payload, code)，
	// 无处放 typed error_detail。要让上面这些可区分 reason 真正到达调用方，
	// 需要把签名扩成能带 detail。在那之前调用方只能看到 FAILED_PRECONDITION，
	// 区分不了「等一会儿」和「别试了」——这正是本文件花力气算出 reason 的意义
	// 所在，别在扩签名时把这段逻辑删了。
	_ = reason
	return nil, code
}

// topStateToWire 把内核的 motiongate.State 翻成 wire 枚举。
//
// 未知值映射到 UNSPECIFIED 而不是 panic：内核加了新状态而这里没跟上时，
// 观察方拿到一个「说不清」比拿到一个错误的具体状态安全得多。
func topStateToWire(s motiongate.State) safetyv1.TopState {
	switch s {
	case motiongate.StateNormal:
		return safetyv1.TopState_TOP_STATE_NORMAL
	case motiongate.StateSafetyLatched:
		return safetyv1.TopState_TOP_STATE_SAFETY_LATCHED
	case motiongate.StateOEMRecovery:
		return safetyv1.TopState_TOP_STATE_OEM_RECOVERY
	case motiongate.StateRearmRequired:
		return safetyv1.TopState_TOP_STATE_REARM_REQUIRED
	default:
		return safetyv1.TopState_TOP_STATE_UNSPECIFIED
	}
}

// stopPhaseToWire 把内核的 StopPhase 翻成 wire 枚举。
func stopPhaseToWire(p StopPhase) safetyv1.StopPhase {
	switch p {
	case PhaseRequested:
		return safetyv1.StopPhase_STOP_PHASE_REQUESTED
	case PhaseSent:
		return safetyv1.StopPhase_STOP_PHASE_SENT
	case PhaseProviderAccepted:
		return safetyv1.StopPhase_STOP_PHASE_PROVIDER_ACCEPTED
	case PhaseMCUAcked:
		return safetyv1.StopPhase_STOP_PHASE_MCU_ACKED
	case PhaseOutputDisabled:
		return safetyv1.StopPhase_STOP_PHASE_OUTPUT_DISABLED
	case PhaseStandstillConfirmed:
		return safetyv1.StopPhase_STOP_PHASE_STANDSTILL_CONFIRMED
	case PhaseDeliveryFault:
		return safetyv1.StopPhase_STOP_PHASE_DELIVERY_FAULT
	case PhaseStandstillTimeout:
		return safetyv1.StopPhase_STOP_PHASE_STANDSTILL_TIMEOUT
	default:
		return safetyv1.StopPhase_STOP_PHASE_UNSPECIFIED
	}
}

// recordBuiltin 记一条内建 endpoint 调用审计。
//
// 【必须记】：Rearm 是全系统唯一能让一台已因安全原因停下来的机器重新允许运动
// 的入口。谁在什么时候试图解除停机、成功与否，事后一定会被问到。
func (m *Module) recordBuiltin(caller identity.Caller, action string, ok bool) {
	if m.aud == nil {
		return
	}
	m.aud.Record(context.Background(), audit.Event{
		Action:  action,
		Subject: caller.String(),
		Denied:  !ok,
	})
}
