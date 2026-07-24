// 本文件是 B1(method 级 Dispatch 转发本体)的端到端测试:两条真实拨号连接
// (一条扮演 Caller、一条扮演 Service)跑过真实的 Server.serve,验证
// Request -> Dispatch -> DispatchResult -> Response 的完整往返,以及超时/
// 目标断连/错位结果/准入上限这些边界路径
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

// routingEndpoints 是本文件专用的 EndpointResolver 测试替身。与
// endpoint_wiring_test.go 的 fakeEndpoints 不同之处:它会记住 RegisterEndpoint
// 收到的真实 conn(Service 侧连接的不透明句柄),供 Route() 把它当作 TargetConn
// 返回——这是让 handleRequest 真正把 Dispatch 写到一条【真实】连接所必需的
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

// newRoutingTestServer 构造一个接上 routingEndpoints 的 Server,复用
// selfUIDInvariants/selfRegistry 让当前测试进程的 UID 能通过准入
func newRoutingTestServer(t *testing.T, re *routingEndpoints) (*Server, string) {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "nervud.sock")
	s, err := New(Config{
		SockPath:   sock,
		Log:        discardLog(),
		Auditor:    &fakeRecorder{},
		Invariants: selfUIDInvariants(t),
		Identity:   selfRegistry(t),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
		Endpoints:  re,
		// Component 核对尚未落地;测试显式走开发降级
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

// registerService 在已握手的连接 c 上发送 RegisterEndpoint 并断言收到成功结果
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
		t.Fatal("service 未收到 Dispatch")
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
		t.Fatal("dispatch caller context 未填充 package_id")
	}
	if d.GetRemainingMs() == 0 || d.GetRemainingMs() > defaultMethodTimeoutMs {
		t.Fatalf("remaining_ms = %d,应当落在 (0, %d]", d.GetRemainingMs(), defaultMethodTimeoutMs)
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
		t.Fatal("caller 未收到 Response")
	}
	if resp.GetRequestId() != 7 {
		t.Fatalf("response request_id = %d, want 7", resp.GetRequestId())
	}
	if string(resp.GetSuccess().GetPayload()) != "world" {
		t.Fatalf("response payload = %q, want world", resp.GetSuccess().GetPayload())
	}
}

// Failure.ErrorDetail/PublicMessage 不透传:即使 Service 塞了内容,调用者也只
// 应看到 Code(架构 10.7,没有权威 method schema 可供解码校验)
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
			PublicMessage: "不该被转发的自由文本",
			ErrorDetail:   []byte("不该被转发的 detail bytes"),
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
		t.Fatalf("public_message 不该被透传,got %q", f.GetPublicMessage())
	}
	if len(f.GetErrorDetail()) != 0 {
		t.Fatalf("error_detail 不该被透传,got %q", f.GetErrorDetail())
	}
}

// route_id 存在,但送回结果的连接并非登记的目标连接:没有合法解释,按协议
// 违规关闭(而不是当成未知 route_id 静默丢弃)
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
		t.Fatal("svcA 未收到 Dispatch")
	}

	// svcB(并非登记的目标连接)冒充送回结果
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
		t.Fatal("svc 未收到 Dispatch")
	}
	// 故意不回应 DispatchResult,等清道夫在下一个 tick(250ms)发现超时

	resp := readEnv(t, caller).GetResponse() // readEnv 自带 3s 读超时,足够等到清道夫
	if resp.GetRequestId() != 5 {
		t.Fatalf("response request_id = %d, want 5", resp.GetRequestId())
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED {
		t.Fatalf("code = %v, want DEADLINE_EXCEEDED", code)
	}
}

// 目标连接在 Dispatch 已发出、结果到达之前断开:调用者必须很快(远早于超时)
// 收到 UNAVAILABLE,而不是一直等到 deadline 才发现
func TestDispatch_TargetDisconnectProducesUnavailablePromptly(t *testing.T) {
	re := &routingEndpoints{registerResult: registerSuccessResult(1)}
	_, sock := newRoutingTestServer(t, re)

	svc := dial(t, sock)
	handshake(t, svc)
	registerService(t, svc, 1)

	caller := dial(t, sock)
	handshake(t, caller)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 3, EndpointId: 1, MethodId: 1, // TimeoutMs=0 => 默认 5s
	}}}
	if err := WriteFrame(caller, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}
	if d := readEnv(t, svc).GetDispatch(); d == nil {
		t.Fatal("svc 未收到 Dispatch")
	}

	start := time.Now()
	_ = svc.Close()

	resp := readEnv(t, caller).GetResponse()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("耗时 %v,说明没有在目标断连时立刻完成,而是等到了别的机制", elapsed)
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("code = %v, want UNAVAILABLE", code)
	}
}

// 单连接 in-flight 上限:超出的请求必须立刻被准入拒绝,不产生 Dispatch
// (架构 10.11 的 ConnectionLimits.max_inflight_requests 首次被强制)
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
			t.Fatalf("请求 %d 应当被转发出 Dispatch", i)
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

// enqueue 在 outbox 容量不足时必须把连接当慢消费者关闭并审计,而不是无声地
// 假装排队成功——直接构造 conn(不经过真实 Server.serve)让容量可控,避免依赖
// 操作系统 socket 缓冲区大小这类环境相关因素
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
		outbox:     newOutboundQueue(1), // 容量小到任何 Envelope 都放不下
		writerDone: make(chan struct{}),
	}

	if co.enqueue(pingEnv(1)) {
		t.Fatal("超出容量的 enqueue 应当返回 false")
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF（连接应当已被关闭）", err)
	}
	waitFor(t, "慢消费者被审计", hasAudit(rec, "ipc.SlowConsumerDisconnect", nil))
}
