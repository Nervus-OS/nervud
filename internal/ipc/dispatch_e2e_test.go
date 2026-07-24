package ipc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

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

func (r *routingEndpoints) Route(endpoint.ConnHandle, uint64) (endpoint.RouteInfo, endpoint.RouteError) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		return endpoint.RouteInfo{}, r.routeErr
	}
	return endpoint.RouteInfo{TargetConn: r.serviceConn, ServiceEndpointID: r.serviceEPID}, endpoint.RouteError{}
}

func (r *routingEndpoints) ConnClosed(endpoint.ConnHandle) {}

func registerSuccessResult(epID uint64) *ipcv1.RegisterEndpointResult {
	return &ipcv1.RegisterEndpointResult{
		Outcome: &ipcv1.RegisterEndpointResult_Success{Success: &ipcv1.RegisterEndpointSuccess{EndpointId: epID}},
	}
}

func newRoutingTestServer(t *testing.T, re *routingEndpoints) (*Server, string) {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "nervud.sock")
	s, err := New(Config{
		SockPath:                 sock,
		Log:                      discardLog(),
		Auditor:                  &fakeRecorder{},
		Invariants:               selfUIDInvariants(t),
		Identity:                 selfRegistry(t),
		Permission:               permission.NewRegistry(permission.DefaultCatalog()),
		Endpoints:                re,
		AllowUnverifiedComponent: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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
	re := &routingEndpoints{registerResult: registerSuccessResult(55)}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshake(t, svc)
	registerService(t, svc, 55)

	caller := dial(t, sock)
	handshake(t, caller)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 7, EndpointId: 1, MethodId: 3, Payload: []byte("hello"),
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
	if string(d.GetPayload()) != "hello" {
		t.Fatalf("dispatch payload = %q, want hello", d.GetPayload())
	}
	if d.GetCaller().GetPackageId() == "" {
		t.Fatal("dispatch caller context did not include package_id")
	}
	if d.GetRemainingMs() == 0 || d.GetRemainingMs() > defaultMethodTimeoutMs {
		t.Fatalf("remaining_ms = %d, want a value in (0, %d]", d.GetRemainingMs(), defaultMethodTimeoutMs)
	}

	dr := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{DispatchResult: &ipcv1.DispatchResult{
		RouteId: d.GetRouteId(),
		Outcome: &ipcv1.DispatchResult_Success{Success: &ipcv1.Success{
			Code: ipcv1.StatusCode_STATUS_CODE_OK, Payload: []byte("world"),
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
	if string(resp.GetSuccess().GetPayload()) != "world" {
		t.Fatalf("response payload = %q, want world", resp.GetSuccess().GetPayload())
	}
}

func TestDispatch_FailureDetailNotForwarded(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshake(t, svc)
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
			ErrorDetail:   []byte("untrusted detail bytes that must not be forwarded"),
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

func TestDispatch_ResultFromWrongConnectionIsViolation(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svcA := dial(t, sock)
	handshake(t, svcA)
	registerService(t, svcA, 1)

	svcB := dial(t, sock)
	handshake(t, svcB)

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
	handshake(t, svc)
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
	handshake(t, svc)
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
	handshake(t, svc)
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
