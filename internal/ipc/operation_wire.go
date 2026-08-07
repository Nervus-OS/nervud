// 本文件是 operation 的本地类型 ↔ wire 类型的薄适配层。
//
// 【只做翻译，不做判定】。任何一条 if 如果影响了「能不能」而不是「怎么写成
// 字节」，它就应该在 operation 包或 operation_builtin.go 里，不在这里。
// 一个混进转换层的裁决会绕开审计，因为审计记的是状态机里的转移。
package ipc

import (
	"errors"

	operationv1 "github.com/nervus-os/nervus-ipc/protocol/interface/operationv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/operation"
)

// stateToWire 把内部状态翻成 wire 枚举。
//
// 【未知值映射成 UNSPECIFIED 而不是猜一个】：UNSPECIFIED 在 wire 上是明确的
// 「fail closed」哨兵，客户端不会拿它当任何一种确定状态处理。猜一个会让调用方
// 按一个错误的结论走下去。
func stateToWire(s operation.State) operationv1.OperationState {
	switch s {
	case operation.StatePending:
		return operationv1.OperationState_OPERATION_STATE_PENDING
	case operation.StateRunning:
		return operationv1.OperationState_OPERATION_STATE_RUNNING
	case operation.StateCancelRequested:
		return operationv1.OperationState_OPERATION_STATE_CANCEL_REQUESTED
	case operation.StateSucceeded:
		return operationv1.OperationState_OPERATION_STATE_SUCCEEDED
	case operation.StateFailed:
		return operationv1.OperationState_OPERATION_STATE_FAILED
	case operation.StateCancelled:
		return operationv1.OperationState_OPERATION_STATE_CANCELLED
	default:
		return operationv1.OperationState_OPERATION_STATE_UNSPECIFIED
	}
}

func originToWire(o operation.OriginBinding) *operationv1.OperationOrigin {
	return &operationv1.OperationOrigin{
		InterfaceId:         o.InterfaceID,
		InterfaceMajor:      o.IfaceMajor,
		InterfaceMinor:      o.IfaceMinor,
		MethodId:            o.MethodID,
		InterfaceSchemaHash: append([]byte(nil), o.SchemaHash...),
	}
}

// operationStatusToWire 投影一份快照。
//
// deadline 要翻进 CLOCK_MONOTONIC 绝对纳秒域，与 ExecutionContext 同一时钟。
// 翻不出来（单调时钟不可用）时留 0 而不是失败：调用方最需要的是状态与终态
// 原因，少一个 deadline 不该让整次查询失败。
func operationStatusToWire(op operation.Operation, s *Server) *operationv1.OperationStatus {
	status := &operationv1.OperationStatus{
		OperationId:     op.ID,
		State:           stateToWire(op.State),
		Origin:          originToWire(op.Origin),
		ResourceHandles: append([]string(nil), op.Resources...),
		MotionEpoch:     op.MotionEpoch,
		TerminalCode:    op.TerminalStatus,
		TerminalResult:  append([]byte(nil), op.TerminalResult...),
		TerminalError:   append([]byte(nil), op.TerminalError...),
	}
	if nanos, err := s.monotonicDeadlineNanos(op.Deadline); err == nil {
		status.DeadlineNanos = nanos
	}
	return status
}

func eventKindToWire(k operation.EventKind) operationv1.OperationEventKind {
	switch k {
	case operation.EventProgress:
		return operationv1.OperationEventKind_OPERATION_EVENT_KIND_PROGRESS
	case operation.EventState:
		return operationv1.OperationEventKind_OPERATION_EVENT_KIND_STATE
	default:
		return operationv1.OperationEventKind_OPERATION_EVENT_KIND_UNSPECIFIED
	}
}

func operationEventToWire(ev operation.Event) *operationv1.OperationEvent {
	return &operationv1.OperationEvent{
		OperationId:    ev.OperationID,
		Kind:           eventKindToWire(ev.Kind),
		State:          stateToWire(ev.State),
		Origin:         originToWire(ev.Origin),
		Progress:       append([]byte(nil), ev.Payload...),
		TerminalCode:   ev.TerminalStatus,
		TerminalResult: append([]byte(nil), ev.TerminalResult...),
		TerminalError:  append([]byte(nil), ev.TerminalError...),
	}
}

// operationAcceptedResponse 把 Provider 的一次 ACCEPTED 翻成带 OperationHandle
// 的终结响应。
//
// 【句柄由内核写】：operation_id 由 nervud 分配、状态机也归 nervud。Provider
// 的 Success.payload 必须为空——非空说明它试图自己造一个句柄，那会让调用方
// 拿到一个 nervud 不认识的编号，而取消与订阅都会静默失效。
func (s *Server) operationAcceptedResponse(
	entry *routeEntry, success *ipcv1.Success,
) (*ipcv1.Response, bool) {
	if len(success.GetPayload()) != 0 {
		return s.rejectProviderResult(entry,
			errors.New("ipc: Provider set a payload on an operation ACCEPTED"))
	}
	operationID := entry.execution.GetOperationId()
	if operationID == 0 {
		// dispatch 那侧本该已经建好 operation 并填进 ExecutionContext。
		// 走到这里说明两处不一致——把它当 Provider 违规拒掉是错的，
		// 但也不能放行一个没有句柄的 ACCEPTED：调用方会以为自己拿到了
		// 一个长任务，然后永远查不到它。
		return s.rejectProviderResult(entry,
			errors.New("ipc: operation ACCEPTED without an operation id"))
	}

	// 长任务【不携带 Transfer 句柄】：数据面的建立走 OpenStream 一类的普通
	// 方法。这里明确以「无句柄」结束 route，避免一条已经准备好的管子悬空。
	if err := s.transfer.FinishRoute(entry.routeID, true, nil); err != nil {
		return s.rejectProviderResult(entry, err)
	}

	payload, err := proto.Marshal(&operationv1.OperationHandle{OperationId: operationID})
	if err != nil {
		return s.rejectProviderResult(entry, err)
	}
	return &ipcv1.Response{
		RequestId: entry.sourceRequestID,
		Outcome: &ipcv1.Response_Success{Success: &ipcv1.Success{
			Code:    ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
			Payload: payload,
		}},
	}, true
}

// operationFailure 构造一个带 typed detail 的内建失败。
func operationFailure(
	code ipcv1.StatusCode, reason operationv1.OperationReason,
) endpoint.BuiltinResult {
	detail, err := proto.Marshal(&operationv1.OperationErrorDetail{Reason: reason})
	if err != nil {
		// detail 编不出来不该让失败变成一个没有 code 的响应：
		// code 本身携带了最要紧的信息（该不该重试），保住它。
		return endpoint.BuiltinResult{Code: code}
	}
	// 【ErrorDetail 而不是 Payload】：后者是成功时的响应载荷，类型由
	// response_type 决定。放错字段的表现是调用方按错误的类型去解一段字节。
	return endpoint.BuiltinResult{ErrorDetail: detail, Code: code}
}

// operationErrToResult 把 operation 包的哨兵错误翻成 (code, typed reason)。
//
// 外层 code 决定 SDK 的恢复行为，reason 决定人能不能看懂发生了什么。
// 两者必须一致——code 说「前置不满足」而 reason 说「找不到」，会让排查
// 从一开始就走错方向。
func operationErrToResult(err error) endpoint.BuiltinResult {
	switch {
	case errors.Is(err, operation.ErrNotFound):
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			operationv1.OperationReason_OPERATION_REASON_NOT_FOUND)
	case errors.Is(err, operation.ErrAlreadyTerminal):
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			operationv1.OperationReason_OPERATION_REASON_ALREADY_TERMINAL)
	case errors.Is(err, operation.ErrStaleEpoch):
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			operationv1.OperationReason_OPERATION_REASON_STALE_EPOCH)
	case errors.Is(err, operation.ErrIllegalTransition):
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			operationv1.OperationReason_OPERATION_REASON_INVALID_TRANSITION)
	default:
		// 认不出来的错误归一化为 INTERNAL + UNSPECIFIED。不猜一个具体原因：
		// 猜错会让 Provider 按错误的结论重试或放弃。
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			operationv1.OperationReason_OPERATION_REASON_UNSPECIFIED)
	}
}
