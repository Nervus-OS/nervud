// 本文件验证 ipc 与 internal/endpoint 的接线（架构总览 §7 待办列表里的那一条）：
// ResolveEndpoint/RegisterEndpoint/UnregisterEndpoint 转发给 EndpointResolver，
// handleRequest 在 Route 之后才决定失败码，ConnClosed 在连接退出时被调用一次
package ipc

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

// fakeEndpoints 是最小的 EndpointResolver 测试替身，记录调用并按需返回固定结果
type fakeEndpoints struct {
	mu sync.Mutex

	resolveResult  *ipcv1.ResolveEndpointResult
	registerResult *ipcv1.RegisterEndpointResult
	unregResult    *ipcv1.UnregisterEndpointResult
	routeInfo      endpoint.RouteInfo
	routeErr       endpoint.RouteError

	connClosed []endpoint.ConnHandle
}

func (f *fakeEndpoints) ResolveEndpoint(conn endpoint.ConnHandle, caller identity.Caller, req *ipcv1.ResolveEndpoint) *ipcv1.ResolveEndpointResult {
	return f.resolveResult
}

func (f *fakeEndpoints) RegisterEndpoint(conn endpoint.ConnHandle, caller identity.Caller, req *ipcv1.RegisterEndpoint) *ipcv1.RegisterEndpointResult {
	return f.registerResult
}

func (f *fakeEndpoints) UnregisterEndpoint(conn endpoint.ConnHandle, req *ipcv1.UnregisterEndpoint) *ipcv1.UnregisterEndpointResult {
	return f.unregResult
}

func (f *fakeEndpoints) Route(conn endpoint.ConnHandle, endpointID uint64) (endpoint.RouteInfo, endpoint.RouteError) {
	return f.routeInfo, f.routeErr
}

func (f *fakeEndpoints) ConnClosed(conn endpoint.ConnHandle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connClosed = append(f.connClosed, conn)
}

func (f *fakeEndpoints) closedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.connClosed)
}

// newTestServerWithEndpoints 构造一个接上 fakeEndpoints 的 Server
func newTestServerWithEndpoints(t *testing.T, inv *authority.Invariants, fe *fakeEndpoints) (*Server, string) {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "nervud.sock")
	s, err := New(Config{
		SockPath:   sock,
		Log:        discardLog(),
		Auditor:    &fakeRecorder{},
		Invariants: inv,
		Identity:   selfRegistry(t),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
		Endpoints:  fe,
		// Component 核对尚未落地；测试显式走开发降级，否则握手会 fail closed
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

func TestReady_ResolveEndpointDispatchesToResolver(t *testing.T) {
	inv := selfUIDInvariants(t)
	fe := &fakeEndpoints{resolveResult: &ipcv1.ResolveEndpointResult{
		RequestId: 5,
		Outcome: &ipcv1.ResolveEndpointResult_Success{Success: &ipcv1.ResolveEndpointSuccess{
			EndpointId: 42,
		}},
	}}
	_, sock := newTestServerWithEndpoints(t, inv, fe)

	c := dial(t, sock)
	handshake(t, c)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_ResolveEndpoint{ResolveEndpoint: &ipcv1.ResolveEndpoint{
		RequestId: 5, InterfaceId: "nervus.interface.motion.base",
	}}}
	if err := WriteFrame(c, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}

	result := readEnv(t, c).GetResolveEndpointResult()
	if result == nil {
		t.Fatal("want ResolveEndpointResult")
	}
	if got := result.GetSuccess().GetEndpointId(); got != 42 {
		t.Fatalf("endpoint_id = %d, want 42 (未真正转发给 EndpointResolver)", got)
	}
}

func TestReady_RegisterEndpointDispatchesToResolver(t *testing.T) {
	inv := selfUIDInvariants(t)
	fe := &fakeEndpoints{registerResult: &ipcv1.RegisterEndpointResult{
		RequestId: 7,
		Outcome: &ipcv1.RegisterEndpointResult_Success{Success: &ipcv1.RegisterEndpointSuccess{
			EndpointId: 9,
		}},
	}}
	_, sock := newTestServerWithEndpoints(t, inv, fe)

	c := dial(t, sock)
	handshake(t, c)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_RegisterEndpoint{RegisterEndpoint: &ipcv1.RegisterEndpoint{
		RequestId: 7, InterfaceId: "nervus.interface.motion.base",
	}}}
	if err := WriteFrame(c, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}

	result := readEnv(t, c).GetRegisterEndpointResult()
	if result == nil {
		t.Fatal("want RegisterEndpointResult")
	}
	if got := result.GetSuccess().GetEndpointId(); got != 9 {
		t.Fatalf("endpoint_id = %d, want 9", got)
	}
}

// Request 在 Endpoints 接线之后：Route 命中 NOT_FOUND 必须原样反映到 Response
// 的失败码，而不是恒 UNAVAILABLE——证明 handleRequest 真的调用了 Route
func TestReady_RequestReflectsRouteNotFound(t *testing.T) {
	inv := selfUIDInvariants(t)
	fe := &fakeEndpoints{routeErr: endpoint.RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}}
	_, sock := newTestServerWithEndpoints(t, inv, fe)

	c := dial(t, sock)
	handshake(t, c)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 3, EndpointId: 123, MethodId: 1,
	}}}
	if err := WriteFrame(c, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}

	resp := readEnv(t, c).GetResponse()
	if resp == nil {
		t.Fatal("want Response")
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("failure code = %v, want NOT_FOUND (Route 未被真正调用？)", code)
	}
}

// Request 在 Route 成功之后：Dispatch 转发本体不在 internal/endpoint 范围内，
// v1 仍以 UNAVAILABLE 收尾——但这是【真正 Route 之后】的 UNAVAILABLE
func TestReady_RequestAfterSuccessfulRouteStillUnavailable(t *testing.T) {
	inv := selfUIDInvariants(t)
	fe := &fakeEndpoints{routeErr: endpoint.RouteError{}} // 零值 = 成功
	_, sock := newTestServerWithEndpoints(t, inv, fe)

	c := dial(t, sock)
	handshake(t, c)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 4, EndpointId: 1, MethodId: 1,
	}}}
	if err := WriteFrame(c, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}

	resp := readEnv(t, c).GetResponse()
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("failure code = %v, want UNAVAILABLE", code)
	}
}

// 连接退出（正常关闭）必须触发恰好一次 ConnClosed，让 endpoint 清理该连接
// 名下的全部 registration/binding（设计方案 §5.4）
func TestConnClosed_CalledOnceOnDisconnect(t *testing.T) {
	inv := selfUIDInvariants(t)
	fe := &fakeEndpoints{}
	s, sock := newTestServerWithEndpoints(t, inv, fe)

	c := dial(t, sock)
	handshake(t, c)
	_ = c.Close()

	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })
	waitFor(t, "ConnClosed 被调用", func() bool { return fe.closedCount() == 1 })
}
