package ipc

import (
	"testing"
	"time"

	operationv1 "github.com/nervus-os/nervus-ipc/protocol/interface/operationv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/operation"
)

// 本文件走完整条长任务链路：
//
//	App --Request(returns_operation)--> nervud
//	                nervud 建 Operation(PENDING)，operation_id 进 ExecutionContext
//	                nervud --Dispatch--> Provider
//	                nervud <--DispatchResult{ACCEPTED}-- Provider
//	App <--Response{ACCEPTED, OperationHandle}-- nervud
//
// 单元测试覆盖不到的正是这个【顺序】：Operation 必须在 Dispatch 之前就存在，
// 否则 Provider 回 ACCEPTED 会被 protocheck 当成违规。

// newOperationTestServer 造一个接了 Operation Manager 的路由服务器。
func newOperationTestServer(t *testing.T, re *routingEndpoints) (*Server, *operation.Manager, string) {
	t.Helper()

	ops := operation.New(
		fakeOperationResources{},
		nil, // 非运动类用例不需要租约校验
		&fakeRecorder{},
		discardLog(),
	)
	s, sock := newRoutingTestServerWithOperations(t, re, ops)
	return s, ops, sock
}

// systemView 是「系统视角」的 caller：canSee 对空 PackageID 放行。
// 测试用它读任意 operation，不必去猜测试连接被解析成了哪个包。
func systemView() identity.Caller { return identity.Caller{} }

// fakeOperationResources 让任何句柄都算有效——资源校验本身由
// internal/operation 的单测覆盖，本文件验的是 wire 顺序。
type fakeOperationResources struct{}

func (fakeOperationResources) Valid(string) bool { return true }

// operationRequest 发起一次 returns_operation 的调用。
func operationRequest(reqID uint64) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: reqID, EndpointId: 1, MethodId: 1,
	}}}
}

// 【Operation 必须在 Dispatch 之前建好】。
//
// Provider 收到 Dispatch 时 operation_id 已经有效，因此它可以直接回
// DispatchResult{ACCEPTED}——那个码要求「Operation 必须已经存在」。
//
// 顺序反过来（先 Dispatch 再建）会产生一个窗口：Provider 已经开始动，而
// operation 还不存在，它的第一次 ReportProgress 会被拒。
func TestOperation_IDReachesProviderBeforeDispatchResult(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		returnsOper:    true,
		resourceHandle: "arm.main",
		resourceGen:    1,
	}
	_, ops, sock := newOperationTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 55)

	caller := dial(t, sock)
	handshake(t, caller)

	if err := WriteFrame(caller, mustMarshal(t, operationRequest(2))); err != nil {
		t.Fatal(err)
	}

	dispatch := readEnv(t, svc).GetDispatch()
	if dispatch == nil {
		t.Fatal("want Dispatch")
	}
	operationID := dispatch.GetExecutionContext().GetOperationId()
	if operationID == 0 {
		t.Fatal("ExecutionContext 没带 operation_id——Provider 无从知道自己在为哪个 operation 干活")
	}
	// 此刻 operation 必须已经存在且处于 PENDING。
	op, ok := ops.Get(systemView(), operationID)
	if !ok {
		t.Fatalf("operation %d 在 Dispatch 时还不存在", operationID)
	}
	if op.State != operation.StatePending {
		t.Fatalf("state = %v, want PENDING", op.State)
	}
}

// Provider 回 ACCEPTED 之后，调用方拿到的是【内核写的】OperationHandle。
func TestOperation_AcceptedResponseCarriesKernelHandle(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		returnsOper:    true,
		resourceHandle: "arm.main",
		resourceGen:    1,
	}
	_, _, sock := newOperationTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 55)

	caller := dial(t, sock)
	handshake(t, caller)
	if err := WriteFrame(caller, mustMarshal(t, operationRequest(2))); err != nil {
		t.Fatal(err)
	}
	dispatch := readEnv(t, svc).GetDispatch()
	operationID := dispatch.GetExecutionContext().GetOperationId()

	// Provider 确认接单。【payload 留空】——句柄归内核写。
	accept := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{
		DispatchResult: &ipcv1.DispatchResult{
			RouteId: dispatch.GetRouteId(),
			Outcome: &ipcv1.DispatchResult_Success{Success: &ipcv1.Success{
				Code: ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
			}},
		},
	}}
	if err := WriteFrame(svc, mustMarshal(t, accept)); err != nil {
		t.Fatal(err)
	}

	resp := readEnv(t, caller).GetResponse()
	success := resp.GetSuccess()
	if success == nil {
		t.Fatalf("want success, got failure %v", resp.GetFailure().GetCode())
	}
	if success.GetCode() != ipcv1.StatusCode_STATUS_CODE_ACCEPTED {
		t.Fatalf("code = %v, want ACCEPTED", success.GetCode())
	}

	var handle operationv1.OperationHandle
	if err := proto.Unmarshal(success.GetPayload(), &handle); err != nil {
		t.Fatalf("ACCEPTED 的载荷不是 OperationHandle: %v", err)
	}
	if handle.GetOperationId() != operationID {
		t.Fatalf("句柄 = %d，Provider 拿到的是 %d——两者必须是同一个",
			handle.GetOperationId(), operationID)
	}
}

// 【Provider 不得自己写句柄】。
//
// operation_id 由 nervud 分配、状态机也归 nervud。让 Provider 填这个字段等于
// 让它指定「调用方拿到的是哪个 operation」——填错或伪造的后果是取消永远取消
// 不到、进度永远收不到，而两边都不报错。
func TestOperation_ProviderCannotForgeHandle(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		returnsOper:    true,
		resourceHandle: "arm.main",
		resourceGen:    1,
	}
	_, _, sock := newOperationTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 55)

	caller := dial(t, sock)
	handshake(t, caller)
	if err := WriteFrame(caller, mustMarshal(t, operationRequest(2))); err != nil {
		t.Fatal(err)
	}
	dispatch := readEnv(t, svc).GetDispatch()

	forged, err := proto.Marshal(&operationv1.OperationHandle{OperationId: 9999})
	if err != nil {
		t.Fatal(err)
	}
	bad := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{
		DispatchResult: &ipcv1.DispatchResult{
			RouteId: dispatch.GetRouteId(),
			Outcome: &ipcv1.DispatchResult_Success{Success: &ipcv1.Success{
				Code:    ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
				Payload: forged,
			}},
		},
	}}
	if err := WriteFrame(svc, mustMarshal(t, bad)); err != nil {
		t.Fatal(err)
	}

	// 调用方拿到失败，而不是那个伪造的句柄。
	resp := readEnv(t, caller).GetResponse()
	if resp.GetSuccess() != nil {
		t.Fatal("伪造的句柄被转发给了调用方")
	}
}

// 【普通方法回 ACCEPTED 仍然违规】：那意味着它声称创建了一个没人拥有的长任务。
func TestOperation_PlainMethodCannotReturnAccepted(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		// returnsOper 留 false
	}
	_, _, sock := newOperationTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 55)

	caller := dial(t, sock)
	handshake(t, caller)
	if err := WriteFrame(caller, mustMarshal(t, operationRequest(2))); err != nil {
		t.Fatal(err)
	}
	dispatch := readEnv(t, svc).GetDispatch()
	if id := dispatch.GetExecutionContext().GetOperationId(); id != 0 {
		t.Fatalf("普通方法的 ExecutionContext 带了 operation_id = %d", id)
	}

	accept := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{
		DispatchResult: &ipcv1.DispatchResult{
			RouteId: dispatch.GetRouteId(),
			Outcome: &ipcv1.DispatchResult_Success{Success: &ipcv1.Success{
				Code: ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
			}},
		},
	}}
	if err := WriteFrame(svc, mustMarshal(t, accept)); err != nil {
		t.Fatal(err)
	}
	resp := readEnv(t, caller).GetResponse()
	if resp.GetSuccess() != nil {
		t.Fatal("普通方法的 ACCEPTED 被放行了")
	}
}

// 没接 Operation Manager 时，长任务方法【被拒】而不是降级成普通调用。
//
// 降级会让调用方拿到一个 OK 而机器还在动，它以为已经做完了。
func TestOperation_RejectedWhenManagerNotWired(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		returnsOper:    true,
	}
	// 走不带 Operations 的构造。
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 55)

	caller := dial(t, sock)
	handshake(t, caller)
	if err := WriteFrame(caller, mustMarshal(t, operationRequest(2))); err != nil {
		t.Fatal(err)
	}

	resp := readEnv(t, caller).GetResponse()
	if resp.GetSuccess() != nil {
		t.Fatal("没有 Operation Manager 却受理了长任务")
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("code = %v, want UNAVAILABLE（能力缺口，不是调用方的错）", code)
	}
}

// dispatch 发布失败时，已经建好的 operation 必须被收敛。
//
// 不收敛的话它会一直挂在 PENDING——Provider 从来没收到过 Dispatch，因此永远
// 不会有人 Accept 或 Complete 它，而调用方已经拿到失败响应、根本不知道它存在。
func TestOperation_ConvergedWhenDispatchFails(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		returnsOper:    true,
		resourceHandle: "arm.main",
		resourceGen:    1,
	}
	_, ops, sock := newOperationTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 55)
	// Provider 断开：Route 仍然返回它，但发布时目标不可用。
	_ = svc.Close()
	waitFor(t, "provider disconnect", func() bool { return true })
	time.Sleep(50 * time.Millisecond)

	caller := dial(t, sock)
	handshake(t, caller)
	if err := WriteFrame(caller, mustMarshal(t, operationRequest(2))); err != nil {
		t.Fatal(err)
	}
	resp := readEnv(t, caller).GetResponse()
	if resp.GetSuccess() != nil {
		t.Fatal("目标已断开却受理了")
	}

	// 不该留下任何非终态的 operation。
	for id := uint64(1); id <= 4; id++ {
		op, ok := ops.Get(systemView(), id)
		if !ok {
			continue
		}
		if !op.State.Terminal() {
			t.Fatalf("operation %d 停在 %v，没有被收敛", id, op.State)
		}
	}
}
