// 本文件把 internal/operation 的状态机接到 wire 上, 形式是一个内建 endpoint:
// nervus.interface.operation.control@1.
//
// # 为什么是内建而不是新的 Envelope body
//
// envelope.proto 的规矩: 想加 body 之前先问它是否属于建立连接 / 发现 endpoint /
// 发起调用 / 返回结果 / 取消 / 订阅 / 推送事件 / 维持连接这八件事之一.
// "查一个 operation 的状态"不属于任何一件 - 它就是一次普通的方法调用.
//
// 所以走内建, 与 Transfer Control 同形: 调用方用完全标准的 Resolve + Request
// 访问, 不知道也不需要知道对面是内核.
//
// # 两组方法, 两种身份
//
//	Get / Cancel 调用方 (创建它的那一个)
//	Accept / ReportProgress / Complete Provider (正在执行它的那一个)
//
// 两组都按连接身份裁决. operation.Manager 的 Get/Cancel 自带 caller 可见性
// 检查; 回报侧的归属由本文件核对 - Provider 只能回报 nervud 派给它的那些.
package ipc

import (
	operationv1 "github.com/nervus-os/nervus-ipc/protocol/interface/operationv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/operation"
	"github.com/nervus-os/nervud/internal/subscription"
)

// InterfaceOperationControl 是本内建接口的 ID.
const InterfaceOperationControl = "nervus.interface.operation.control"

// operationBuiltinEndpointID 是本内建 endpoint 在扇出键里用的 endpoint 号.
//
// 事件扇出的键是 (ProviderConn, EndpointID, EventID, Scope). 内建没有 conn,
// ProviderConn 恒为 nil; EndpointID 取注册时分配的那个. RouteEvent 已经把它
// 填进 EventRoute.ProviderEndpointID, 本文件在装配时记下来供 Publish 用.
//
// 两处必须是同一个数字: 订阅登记用 RouteEvent 给的, 扇出用这里记的,
// 对不上就是订阅方永远收不到事件 - 而两边都不报错.
type operationWire struct {
	s *Server

	// endpointID 由 endpoint 模块在 RegisterBuiltin 时分配, 装配后只读.
	endpointID uint64
}

// OperationBuiltinHandler 返回可交给 endpoint.RegisterBuiltin 的处理函数.
func (s *Server) OperationBuiltinHandler() endpoint.BuiltinHandler {
	w := &operationWire{s: s}
	s.operationWire = w
	return func(call endpoint.BuiltinCall) endpoint.BuiltinResult {
		return w.dispatch(call)
	}
}

// OperationSubscribeAdmitter 返回订阅准入.
//
// 它回答的是"这个调用方能不能观察这个 operation" - 而那正是
// operation.Manager.Get 的可见性规则. 复用它而不是另写一套: 两套规则一旦
// 分叉, 表现是"查得到但订不上"或者反过来, 而两者都合法得看不出问题.
func (s *Server) OperationSubscribeAdmitter() endpoint.BuiltinSubscribeAdmitter {
	return func(call endpoint.BuiltinSubscribeCall) endpoint.BuiltinSubscribeResult {
		if s.operations == nil {
			return endpoint.BuiltinSubscribeResult{
				Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
			}
		}
		if call.EventID != uint32(
			operationv1.OperationControlEvent_OPERATION_CONTROL_EVENT_OPERATION_CHANGED) {
			return endpoint.BuiltinSubscribeResult{
				Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			}
		}

		// scope 就是 operation_id. 内核自己看得懂它, 不需要解 Provider 的 proto.
		//
		// 跨 caller 一律 NOT_FOUND, 不是 PERMISSION_DENIED. 后者会告诉
		// 调用方"这个 operation 存在, 只是不归你" - 那本身就是信息.
		// 与 Manager.Get 的不可区分投影一致.
		if _, ok := s.operations.Get(call.Caller, call.Scope); !ok {
			return endpoint.BuiltinSubscribeResult{
				Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			}
		}
		return endpoint.BuiltinSubscribeResult{Code: ipcv1.StatusCode_STATUS_CODE_OK}
	}
}

// SetOperationEndpointID 记下内建 endpoint 的句柄, 供事件扇出使用.
// 装配期调用一次.
func (s *Server) SetOperationEndpointID(id uint64) {
	if s.operationWire != nil {
		s.operationWire.endpointID = id
	}
}

// OperationEventObserver 返回可交给 operation.Manager.SetEventObserver 的旁路.
//
// 它在 operation.mu 下运行: 只做非阻塞的扇出, 不回调进 operation.
// 锁序固定为 operation.mu -> subscription.mu.
func (s *Server) OperationEventObserver() func(operation.Event) {
	return func(ev operation.Event) {
		s.publishOperationEvent(ev)
	}
}

func (s *Server) publishOperationEvent(ev operation.Event) {
	if s == nil || s.subscriptions == nil || s.operationWire == nil {
		return
	}
	payload, err := proto.Marshal(operationEventToWire(ev))
	if err != nil {
		// 编不出来是本端 bug. 丢弃这一条并记日志 - 把一条编码失败变成
		// 一次 panic 会带走整个 nervud.
		s.log.Error("ipc: marshal OperationEvent", "operation_id", ev.OperationID, "err", err)
		return
	}

	key := subscription.Key{
		ProviderConn: nil, // 内建没有 conn
		EndpointID:   s.operationWire.endpointID,
		EventID: uint32(
			operationv1.OperationControlEvent_OPERATION_CONTROL_EVENT_OPERATION_CHANGED),
		// 按 operation 分: 不这么做, 订阅方会收到全机所有人的进度与失败细因.
		Scope: ev.OperationID,
	}
	closed := s.subscriptions.Publish(key, payload, 0)
	s.closeSubscriptions(closed)

	// 终态之后不会再有事件. 留着订阅只会让调用方一直等 - 明确关掉它,
	// 让它的 range 自然结束.
	if ev.Kind == operation.EventState && ev.State.Terminal() {
		s.closeSubscriptions(s.subscriptions.CloseScope(
			nil, s.operationWire.endpointID, ev.OperationID,
			ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_ENDPOINT_DIED))
	}
}

// dispatch 按 method_id 分派.
func (w *operationWire) dispatch(call endpoint.BuiltinCall) endpoint.BuiltinResult {
	if w == nil || w.s == nil || w.s.operations == nil {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE}
	}
	switch operationv1.OperationControlMethod(call.MethodID) {
	case operationv1.OperationControlMethod_OPERATION_CONTROL_METHOD_GET_OPERATION:
		return w.get(call)
	case operationv1.OperationControlMethod_OPERATION_CONTROL_METHOD_CANCEL_OPERATION:
		return w.cancel(call)
	case operationv1.OperationControlMethod_OPERATION_CONTROL_METHOD_ACCEPT_OPERATION:
		return w.accept(call)
	case operationv1.OperationControlMethod_OPERATION_CONTROL_METHOD_REPORT_PROGRESS:
		return w.reportProgress(call)
	case operationv1.OperationControlMethod_OPERATION_CONTROL_METHOD_COMPLETE_OPERATION:
		return w.complete(call)
	default:
		// fail closed: 没实现的方法就是不存在.
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
}

func (w *operationWire) get(call endpoint.BuiltinCall) endpoint.BuiltinResult {
	var req operationv1.GetOperationRequest
	if err := proto.Unmarshal(call.Payload, &req); err != nil {
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			operationv1.OperationReason_OPERATION_REASON_UNSPECIFIED)
	}
	op, ok := w.s.operations.Get(call.Caller, req.GetOperationId())
	if !ok {
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			operationv1.OperationReason_OPERATION_REASON_NOT_FOUND)
	}
	wire, err := proto.Marshal(operationStatusToWire(op, w.s))
	if err != nil {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL}
	}
	return endpoint.BuiltinResult{Payload: wire, Code: ipcv1.StatusCode_STATUS_CODE_OK}
}

func (w *operationWire) cancel(call endpoint.BuiltinCall) endpoint.BuiltinResult {
	var req operationv1.CancelOperationRequest
	if err := proto.Unmarshal(call.Payload, &req); err != nil {
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			operationv1.OperationReason_OPERATION_REASON_UNSPECIFIED)
	}
	code := w.s.operations.Cancel(call.Caller, req.GetOperationId())
	if code == ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		return operationFailure(code, operationv1.OperationReason_OPERATION_REASON_NOT_FOUND)
	}
	// ACCEPTED 而不是 OK: 取消是请求不是命令. 真正的终态由后续事件给出.
	return endpoint.BuiltinResult{Code: code}
}

// ---- 提供侧 ---------------------------------------------------------------

// providerOperation 校验一次 Provider 回报的归属, 返回被回报的 operation.
//
// Provider 只能回报 nervud 派给它的那些. 少了这道检查, 任何一个系统服务
// 都能把别人的 operation 报成失败 - 而调用方看到的是一次"正常"的失败,
// 连细因都是伪造的那一份.
func (w *operationWire) providerOperation(
	call endpoint.BuiltinCall, id uint64,
) (operation.Operation, endpoint.BuiltinResult, bool) {
	op, ok := w.s.operations.ProviderOperation(call.Conn, id)
	if !ok {
		// 不存在, 或者不是派给这条连接的. 两者同一个回答: 区分开会告诉
		// 调用方"这个 id 存在, 只是不归你", 那本身就是信息.
		return operation.Operation{}, operationFailure(
			ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			operationv1.OperationReason_OPERATION_REASON_NOT_FOUND), false
	}
	return op, endpoint.BuiltinResult{}, true
}

func (w *operationWire) accept(call endpoint.BuiltinCall) endpoint.BuiltinResult {
	var req operationv1.AcceptOperationRequest
	if err := proto.Unmarshal(call.Payload, &req); err != nil {
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			operationv1.OperationReason_OPERATION_REASON_UNSPECIFIED)
	}
	if _, fail, ok := w.providerOperation(call, req.GetOperationId()); !ok {
		return fail
	}
	if err := w.s.operations.Accept(req.GetOperationId(), req.GetMotionEpoch()); err != nil {
		return operationErrToResult(err)
	}
	return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_OK}
}

func (w *operationWire) reportProgress(call endpoint.BuiltinCall) endpoint.BuiltinResult {
	var req operationv1.ReportProgressRequest
	if err := proto.Unmarshal(call.Payload, &req); err != nil {
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			operationv1.OperationReason_OPERATION_REASON_UNSPECIFIED)
	}
	if _, fail, ok := w.providerOperation(call, req.GetOperationId()); !ok {
		return fail
	}
	if err := w.s.operations.Progress(req.GetOperationId(), req.GetProgress()); err != nil {
		return operationErrToResult(err)
	}
	return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_OK}
}

func (w *operationWire) complete(call endpoint.BuiltinCall) endpoint.BuiltinResult {
	var req operationv1.CompleteOperationRequest
	if err := proto.Unmarshal(call.Payload, &req); err != nil {
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			operationv1.OperationReason_OPERATION_REASON_UNSPECIFIED)
	}
	if _, fail, ok := w.providerOperation(call, req.GetOperationId()); !ok {
		return fail
	}

	var err error
	switch req.GetCode() {
	case ipcv1.StatusCode_STATUS_CODE_OK:
		err = w.s.operations.Succeed(req.GetOperationId(), req.GetResult())
	case ipcv1.StatusCode_STATUS_CODE_CANCELLED:
		err = w.s.operations.Cancelled(req.GetOperationId())
	case ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
		ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
		ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
		ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
		ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED,
		ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
		ipcv1.StatusCode_STATUS_CODE_INTERNAL:
		err = w.s.operations.Fail(req.GetOperationId(), req.GetCode(), req.GetErrorDetail())
	default:
		// ACCEPTED / UNAUTHENTICATED / PERMISSION_DENIED 等是内核专属的
		// 裁决结果, 不是执行结果. Provider 写它们等于伪造一次内核判定.
		return operationFailure(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			operationv1.OperationReason_OPERATION_REASON_INVALID_TERMINAL_CODE)
	}
	if err != nil {
		return operationErrToResult(err)
	}
	return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_OK}
}
