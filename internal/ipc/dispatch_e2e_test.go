package ipc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

type routingEndpoints struct {
	mu sync.Mutex

	serviceConn endpoint.ConnHandle
	serviceEPID uint64

	registerResult *ipcv1.RegisterEndpointResult
	routeErr       endpoint.RouteError
	required       []string
	resourceHandle string
	resourceGen    uint64
	requiresLease  bool
	isMotion       bool
	// returnsOper 让这个替身声明一个长任务方法。
	returnsOper bool
}

func (r *routingEndpoints) ResolveEndpoint(endpoint.ConnHandle, identity.Caller, *ipcv1.ResolveEndpoint) *ipcv1.ResolveEndpointResult {
	return &ipcv1.ResolveEndpointResult{}
}

func (r *routingEndpoints) RegisterEndpoint(conn endpoint.ConnHandle, _ identity.Caller, _ *ipcv1.RegisterEndpoint) *ipcv1.RegisterEndpointResult {
	r.mu.Lock()
	r.serviceConn = conn
	if s := r.registerResult.GetSuccess(); s != nil {
		r.serviceEPID = s.GetEndpointId()
	}
	r.mu.Unlock()
	return r.registerResult
}

func (r *routingEndpoints) UnregisterEndpoint(_ endpoint.ConnHandle, req *ipcv1.UnregisterEndpoint) *ipcv1.UnregisterEndpointResult {
	return &ipcv1.UnregisterEndpointResult{RequestId: req.GetRequestId(), Outcome: &ipcv1.UnregisterEndpointResult_Success{
		Success: &ipcv1.UnregisterEndpointSuccess{},
	}}
}

// 订阅链路在本文件的用例里不参与——这两个替身恒回 NOT_FOUND。
// 订阅本身的行为由 internal/subscription 与 subscribe_test.go 覆盖。
func (r *routingEndpoints) RouteEvent(
	_ endpoint.ConnHandle, _ uint64, _ uint32,
) (endpoint.EventRoute, endpoint.RouteError) {
	return endpoint.EventRoute{}, endpoint.RouteError{
		Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
	}
}

func (r *routingEndpoints) LookupProviderEvent(
	_ endpoint.ConnHandle, _ uint64, _ uint32,
) (catalog.EventDefinition, endpoint.RouteError) {
	return catalog.EventDefinition{}, endpoint.RouteError{
		Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
	}
}

func (r *routingEndpoints) Route(
	_ endpoint.ConnHandle,
	_ uint64,
	methodID uint32,
) (endpoint.RouteInfo, endpoint.RouteError) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		return endpoint.RouteInfo{}, r.routeErr
	}
	descriptor := (&wrapperspb.StringValue{}).ProtoReflect().Descriptor()
	return endpoint.RouteInfo{
		TargetConn:          r.serviceConn,
		ServiceEndpointID:   r.serviceEPID,
		InterfaceID:         "com.example.test.echo",
		InterfaceMajor:      1,
		RequiredPermissions: append([]string(nil), r.required...),
		ResourceHandle:      r.resourceHandle,
		ResourceGeneration:  r.resourceGen,
		Method: catalog.MethodDefinition{
			InterfaceID: "com.example.test.echo",
			Major:       1,
			MethodID:    methodID,
			Meta: &ipcv1.MethodMeta{
				MethodId:             methodID,
				RiskClass:            ipcv1.RiskClass_RISK_CLASS_NORMAL,
				RequestType:          string(descriptor.FullName()),
				ResponseType:         string(descriptor.FullName()),
				DefaultTimeoutMs:     defaultMethodTimeoutMs,
				MaxTimeoutMs:         maxMethodTimeoutMs,
				ReturnsOperation:     r.returnsOper,
				RequiresControlLease: r.requiresLease,
				IsMotion:             r.isMotion,
			},
			Request:  descriptor,
			Response: descriptor,
		},
	}, endpoint.RouteError{}
}

func (r *routingEndpoints) ConnClosed(endpoint.ConnHandle) {}

func registerSuccessResult(epID uint64) *ipcv1.RegisterEndpointResult {
	return &ipcv1.RegisterEndpointResult{
		Outcome: &ipcv1.RegisterEndpointResult_Success{Success: &ipcv1.RegisterEndpointSuccess{EndpointId: epID}},
	}
}

func newRoutingTestServer(
	t *testing.T,
	re *routingEndpoints,
	leaseValues ...ControlLeases,
) (*Server, string) {
	t.Helper()
	var leases ControlLeases
	if len(leaseValues) != 0 {
		leases = leaseValues[0]
	}
	return newRoutingTestServerWith(t, re, leases, nil)
}

// newRoutingTestServerWithOperations 是接了 Operation Manager 的变体。
func newRoutingTestServerWithOperations(
	t *testing.T, re *routingEndpoints, ops OperationManager,
) (*Server, string) {
	t.Helper()
	return newRoutingTestServerWith(t, re, nil, ops)
}

func newRoutingTestServerWith(
	t *testing.T,
	re *routingEndpoints,
	leases ControlLeases,
	ops OperationManager,
) (*Server, string) {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "nervud.sock")
	s, err := New(Config{
		SockPath:   sock,
		Log:        discardLog(),
		Auditor:    &fakeRecorder{},
		Invariants: selfUIDInvariants(t),
		Identity:   selfRegistry(t),
		Permission: permission.NewDefaultRegistry(),
		Endpoints:  re,
		Leases:     leases,
		Resources:  fakeResources{},
		Operations: ops,
		Transfer:   newTestTransfer(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.monotonicNow = func() (uint64, error) { return uint64(10 * time.Second), nil }
	installTestComponentVerifier(s)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	})
	return s, sock
}

func registerService(t *testing.T, c net.Conn, epID uint64) {
	t.Helper()
	reg := &ipcv1.Envelope{Body: &ipcv1.Envelope_RegisterEndpoint{RegisterEndpoint: &ipcv1.RegisterEndpoint{
		RequestId: 1, InterfaceId: "nervus.interface.motion.base",
	}}}
	if err := WriteFrame(c, mustMarshal(t, reg)); err != nil {
		t.Fatal(err)
	}
	got := readEnv(t, c).GetRegisterEndpointResult().GetSuccess().GetEndpointId()
	if got != epID {
		t.Fatalf("register endpoint_id = %d, want %d", got, epID)
	}
}

func TestDispatch_FullRoundTrip(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		required:       []string{"perm.test.echo", "perm.test.audit"},
	}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 55)

	caller := dial(t, sock)
	handshake(t, caller)

	hello, err := proto.Marshal(&wrapperspb.StringValue{Value: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 7, EndpointId: 1, MethodId: 3, Payload: hello,
	}}}
	if err := WriteFrame(caller, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}

	d := readEnv(t, svc).GetDispatch()
	if d == nil {
		t.Fatal("service did not receive Dispatch")
	}
	if d.GetEndpointId() != 55 {
		t.Fatalf("dispatch endpoint_id = %d, want 55", d.GetEndpointId())
	}
	if d.GetMethodId() != 3 {
		t.Fatalf("dispatch method_id = %d, want 3", d.GetMethodId())
	}
	var dispatched wrapperspb.StringValue
	if err := proto.Unmarshal(d.GetPayload(), &dispatched); err != nil || dispatched.GetValue() != "hello" {
		t.Fatalf("dispatch payload = %q, err=%v", dispatched.GetValue(), err)
	}
	if d.GetCaller().GetPackageId() == "" {
		t.Fatal("dispatch caller context did not include package_id")
	}
	if got := d.GetCaller().GetGrantedPermissions(); !reflect.DeepEqual(got, re.required) {
		t.Fatalf("dispatch granted_permissions = %v, want %v", got, re.required)
	}
	if d.GetRemainingMs() == 0 || d.GetRemainingMs() > defaultMethodTimeoutMs {
		t.Fatalf("remaining_ms = %d, want a value in (0, %d]", d.GetRemainingMs(), defaultMethodTimeoutMs)
	}
	if ec := d.GetExecutionContext(); ec == nil || ec.GetDeadlineNanos() <= 0 ||
		ec.GetLeaseId() != 0 || ec.GetCommandSequence() != 0 {
		t.Fatalf("plain dispatch execution context = %+v", ec)
	}

	world, err := proto.Marshal(&wrapperspb.StringValue{Value: "world"})
	if err != nil {
		t.Fatal(err)
	}
	dr := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{DispatchResult: &ipcv1.DispatchResult{
		RouteId: d.GetRouteId(),
		Outcome: &ipcv1.DispatchResult_Success{Success: &ipcv1.Success{
			Code: ipcv1.StatusCode_STATUS_CODE_OK, Payload: world,
		}},
	}}}
	if err := WriteFrame(svc, mustMarshal(t, dr)); err != nil {
		t.Fatal(err)
	}

	resp := readEnv(t, caller).GetResponse()
	if resp == nil {
		t.Fatal("caller did not receive Response")
	}
	if resp.GetRequestId() != 7 {
		t.Fatalf("response request_id = %d, want 7", resp.GetRequestId())
	}
	var returned wrapperspb.StringValue
	if err := proto.Unmarshal(resp.GetSuccess().GetPayload(), &returned); err != nil || returned.GetValue() != "world" {
		t.Fatalf("response payload = %q, err=%v", returned.GetValue(), err)
	}
}

func TestDispatch_ControlExecutionContextUsesLeaseProof(t *testing.T) {
	re := &routingEndpoints{
		registerResult: registerSuccessResult(55),
		resourceHandle: "base.main",
		resourceGen:    11,
		requiresLease:  true,
		isMotion:       true,
	}
	leases := &fakeLeases{}
	_, sock := newRoutingTestServer(t, re, leases)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 55)

	caller := dial(t, sock)
	handshake(t, caller)
	if err := WriteFrame(caller, mustMarshal(t, acquireEnv(
		1, ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, nil,
	))); err != nil {
		t.Fatal(err)
	}
	lease := readEnv(t, caller).GetAcquireControlResult().GetSuccess()
	if lease == nil {
		t.Fatal("control lease was not acquired")
	}

	var previousSequence uint64
	for requestID := uint64(2); requestID <= 3; requestID++ {
		req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
			RequestId: requestID, EndpointId: 1, MethodId: 1,
		}}}
		if err := WriteFrame(caller, mustMarshal(t, req)); err != nil {
			t.Fatal(err)
		}
		dispatch := readEnv(t, svc).GetDispatch()
		ec := dispatch.GetExecutionContext()
		if ec == nil || ec.GetLeaseId() != lease.GetLeaseId() ||
			ec.GetControllerClass() != ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN ||
			ec.GetMotionEpoch() != lease.GetMotionEpoch() ||
			ec.GetResourceHandle() != "base.main" || ec.GetResourceGeneration() != 11 ||
			ec.GetDeadlineNanos() <= 0 || ec.GetDeadlineNanos() > lease.GetDeadlineNanos() ||
			ec.GetCommandSequence() <= previousSequence {
			t.Fatalf("control execution context = %+v, lease = %+v", ec, lease)
		}
		previousSequence = ec.GetCommandSequence()
	}
}

// v1 曾按协商 minor 决定 Dispatch 带不带 ExecutionContext，因此需要一条
// 「minor 0 的 Provider 拿不到控制方法」的规则，以及它对应的测试。
//
// v2 从第一天起无条件携带，那条规则与测试一并移除。控制方法的准入现在只看
// 租约证明本身（见 TestDispatch_ControlExecutionContextUsesLeaseProof）。

func TestDispatch_ProviderPublicMessageNotForwarded(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 1)

	caller := dial(t, sock)
	handshake(t, caller)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 1, EndpointId: 1, MethodId: 1,
	}}}
	if err := WriteFrame(caller, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}
	d := readEnv(t, svc).GetDispatch()

	dr := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{DispatchResult: &ipcv1.DispatchResult{
		RouteId: d.GetRouteId(),
		Outcome: &ipcv1.DispatchResult_Failure{Failure: &ipcv1.Failure{
			Code:          ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			PublicMessage: "untrusted free-form text that must not be forwarded",
		}},
	}}}
	if err := WriteFrame(svc, mustMarshal(t, dr)); err != nil {
		t.Fatal(err)
	}

	resp := readEnv(t, caller).GetResponse()
	f := resp.GetFailure()
	if f.GetCode() != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("code = %v, want FAILED_PRECONDITION", f.GetCode())
	}
	if f.GetPublicMessage() != "" {
		t.Fatalf("public_message must not pass through, got %q", f.GetPublicMessage())
	}
	if len(f.GetErrorDetail()) != 0 {
		t.Fatalf("error_detail must not pass through, got %q", f.GetErrorDetail())
	}
}

func TestDispatch_UnmappedProviderErrorDetailIsContractViolation(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 1)

	caller := dial(t, sock)
	handshake(t, caller)
	request := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 2, EndpointId: 1, MethodId: 1,
	}}}
	if err := WriteFrame(caller, mustMarshal(t, request)); err != nil {
		t.Fatal(err)
	}
	dispatch := readEnv(t, svc).GetDispatch()

	result := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{DispatchResult: &ipcv1.DispatchResult{
		RouteId: dispatch.GetRouteId(),
		Outcome: &ipcv1.DispatchResult_Failure{Failure: &ipcv1.Failure{
			Code:        ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ErrorDetail: []byte{1, 2, 3},
		}},
	}}}
	if err := WriteFrame(svc, mustMarshal(t, result)); err != nil {
		t.Fatal(err)
	}

	response := readEnv(t, caller).GetResponse()
	if code := response.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_INTERNAL {
		t.Fatalf("response code = %v, want INTERNAL", code)
	}
	expectClosed(t, svc)
}

func TestDispatch_ResultFromWrongConnectionIsViolation(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svcA := dial(t, sock)
	handshakeService(t, svcA)
	registerService(t, svcA, 1)

	svcB := dial(t, sock)
	handshakeService(t, svcB)

	caller := dial(t, sock)
	handshake(t, caller)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 9, EndpointId: 1, MethodId: 1,
	}}}
	if err := WriteFrame(caller, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}
	d := readEnv(t, svcA).GetDispatch()
	if d == nil {
		t.Fatal("svcA did not receive Dispatch")
	}

	dr := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{DispatchResult: &ipcv1.DispatchResult{
		RouteId: d.GetRouteId(),
	}}}
	if err := WriteFrame(svcB, mustMarshal(t, dr)); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, svcB)
}

func TestDispatch_TimeoutProducesDeadlineExceeded(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 1)

	caller := dial(t, sock)
	handshake(t, caller)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 5, EndpointId: 1, MethodId: 1, TimeoutMs: 50,
	}}}
	if err := WriteFrame(caller, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}
	if d := readEnv(t, svc).GetDispatch(); d == nil {
		t.Fatal("svc did not receive Dispatch")
	}

	resp := readEnv(t, caller).GetResponse()
	if resp.GetRequestId() != 5 {
		t.Fatalf("response request_id = %d, want 5", resp.GetRequestId())
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED {
		t.Fatalf("code = %v, want DEADLINE_EXCEEDED", code)
	}
}

func TestDispatch_TargetDisconnectProducesUnavailablePromptly(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 1)

	caller := dial(t, sock)
	handshake(t, caller)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 3, EndpointId: 1, MethodId: 1,
	}}}
	if err := WriteFrame(caller, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}
	if d := readEnv(t, svc).GetDispatch(); d == nil {
		t.Fatal("svc did not receive Dispatch")
	}

	start := time.Now()
	_ = svc.Close()

	resp := readEnv(t, caller).GetResponse()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("elapsed %v; completion did not happen immediately when the target disconnected", elapsed)
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("code = %v, want UNAVAILABLE", code)
	}
}

func TestDispatch_AdmissionCapRejectsExcessInFlight(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshakeService(t, svc)
	registerService(t, svc, 1)

	caller := dial(t, sock)
	handshake(t, caller)

	for i := uint64(1); i <= maxInflightRequests; i++ {
		req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
			RequestId: i, EndpointId: 1, MethodId: 1,
		}}}
		if err := WriteFrame(caller, mustMarshal(t, req)); err != nil {
			t.Fatal(err)
		}
		if d := readEnv(t, svc).GetDispatch(); d == nil {
			t.Fatalf("request %d should be forwarded as Dispatch", i)
		}
	}

	over := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: maxInflightRequests + 1, EndpointId: 1, MethodId: 1,
	}}}
	if err := WriteFrame(caller, mustMarshal(t, over)); err != nil {
		t.Fatal(err)
	}

	resp := readEnv(t, caller).GetResponse()
	if resp.GetRequestId() != maxInflightRequests+1 {
		t.Fatalf("response request_id = %d, want %d", resp.GetRequestId(), maxInflightRequests+1)
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED {
		t.Fatalf("code = %v, want RESOURCE_EXHAUSTED", code)
	}
}

func TestConn_EnqueueOverflowClosesAsSlowConsumer(t *testing.T) {
	rec := &fakeRecorder{}
	s := &Server{
		log:          discardLog(),
		auditor:      rec,
		violationLog: newRateLimiter(10, time.Second),
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	co := &conn{
		s:          s,
		c:          server,
		w:          bufio.NewWriter(server),
		log:        discardLog(),
		caller:     identity.Caller{PackageID: "com.nervus.test"},
		outbox:     newOutboundQueue(1),
		writerDone: make(chan struct{}),
	}

	if co.enqueue(pingEnv(1)) {
		t.Fatal("enqueue beyond capacity should return false")
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF because the connection should be closed", err)
	}
	waitFor(t, "slow consumer audit", hasAudit(rec, "ipc.SlowConsumerDisconnect", nil))
}
