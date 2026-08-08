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

//
//	App -> nervud: Request(returns_operation)

//	                nervud -> Provider: Dispatch
//	                nervud <--DispatchResult{ACCEPTED}-- Provider
//	App <--Response{ACCEPTED, OperationHandle}-- nervud
//

func newOperationTestServer(t *testing.T, re *routingEndpoints) (*Server, *operation.Manager, string) {
	t.Helper()

	ops := operation.New(
		fakeOperationResources{},
		nil,
		&fakeRecorder{},
		discardLog(),
	)
	s, sock := newRoutingTestServerWithOperations(t, re, ops)
	return s, ops, sock
}

func systemView() identity.Caller { return identity.Caller{} }

type fakeOperationResources struct{}

func (fakeOperationResources) Valid(string) bool { return true }

func operationRequest(reqID uint64) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: reqID, EndpointId: 1, MethodId: 1,
	}}}
}

//

//

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
		t.Fatal("unexpected ipc result; ExecutionContext operation_id Provider operation")
	}

	op, ok := ops.Get(systemView(), operationID)
	if !ok {
		t.Fatalf("unexpected ipc result; operation %d Dispatch", operationID)
	}
	if op.State != operation.StatePending {
		t.Fatalf("state = %v, want PENDING", op.State)
	}
}

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
		t.Fatalf("unexpected ipc result; ACCEPTED OperationHandle: %v", err)
	}
	if handle.GetOperationId() != operationID {
		t.Fatalf("unexpected ipc result; value = %d Provider %d",
			handle.GetOperationId(), operationID)
	}
}

//

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

	resp := readEnv(t, caller).GetResponse()
	if resp.GetSuccess() != nil {
		t.Fatal("unexpected ipc result")
	}
}

func TestOperation_PlainMethodCannotReturnAccepted(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
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
		t.Fatalf("unexpected ipc result; ExecutionContext operation_id = %d", id)
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
		t.Fatal("unexpected ipc result; ACCEPTED")
	}
}

//

func TestOperation_RejectedWhenManagerNotWired(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		returnsOper:    true,
	}

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
		t.Fatal("unexpected ipc result; Operation Manager")
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("unexpected ipc result; code = %v, want UNAVAILABLE", code)
	}
}

//

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
		t.Fatal("unexpected ipc result")
	}

	for id := uint64(1); id <= 4; id++ {
		op, ok := ops.Get(systemView(), id)
		if !ok {
			continue
		}
		if !op.State.Terminal() {
			t.Fatalf("unexpected ipc result; operation %d %v", id, op.State)
		}
	}
}
