package ipc

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
)

// helloEnv 构造一个与 nervud 支持版本兼容的 Hello
func helloEnv() *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_Hello{Hello: &ipcv1.Hello{
		MinProtocolMajor: protocolMajor,
		MaxProtocolMajor: protocolMajor,
		MaxProtocolMinor: protocolMinorMax,
		SdkName:          "test",
		SdkVersion:       "0",
	}}}
}

// readEnv 从客户端读回一个完整的 Envelope 帧
func readEnv(t *testing.T, c net.Conn) *ipcv1.Envelope {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := ReadFrameHeader(c)
	if err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	buf := make([]byte, n)
	body, err := ReadFrameBody(c, buf, n)
	if err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	env, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	return env
}

// handshake 发送合法 Hello 并读回成功 HelloAck，返回其 Success
func handshake(t *testing.T, c net.Conn) *ipcv1.HelloAckSuccess {
	t.Helper()
	if err := WriteFrame(c, mustMarshal(t, helloEnv())); err != nil {
		t.Fatalf("write Hello: %v", err)
	}
	ack := readEnv(t, c).GetHelloAck()
	if ack == nil {
		t.Fatal("want HelloAck")
	}
	if f := ack.GetFailure(); f != nil {
		t.Fatalf("handshake failed unexpectedly: code=%v", f.GetCode())
	}
	s := ack.GetSuccess()
	if s == nil {
		t.Fatal("HelloAck 既非 success 也非 failure")
	}
	return s
}

// expectClosed 断言服务端已关闭连接（下一次读得到 EOF）
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF（服务端应当关闭连接）", err)
	}
}

func hasAudit(rec *fakeRecorder, action string, err error) func() bool {
	return func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Action == action && ev.Subject != "" && ev.Subject != "kernel" &&
				(err == nil || errors.Is(ev.Err, err)) {
				return true
			}
		}
		return false
	}
}

// --- 握手 -----------------------------------------------------------------

// 成功握手：回填 package_id、回显协商版本、下发已强制的 ConnectionLimits，
// 之后 Ping→Pong 打通
func TestHandshake_Success(t *testing.T) {
	inv := selfUIDInvariants(t)
	_, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	ack := handshake(t, c)

	if ack.GetProtocolMajor() != protocolMajor || ack.GetProtocolMinor() != protocolMinorMax {
		t.Fatalf("协商版本 = %d.%d, want %d.%d",
			ack.GetProtocolMajor(), ack.GetProtocolMinor(), protocolMajor, protocolMinorMax)
	}
	if ack.GetPackageId() != "com.nervus.test" {
		t.Fatalf("package_id = %q, want com.nervus.test", ack.GetPackageId())
	}
	// Component 核对尚是 stub：确认到的 component_id 为空，而不是相信自报值
	if ack.GetComponentId() != "" {
		t.Fatalf("component_id = %q, want 空（核对未落地不该回填自报值）", ack.GetComponentId())
	}

	lim := ack.GetLimits()
	if lim == nil {
		t.Fatal("HelloAck 未下发 ConnectionLimits")
	}
	if lim.GetMaxFrameBytes() != MaxFrameBytes {
		t.Fatalf("max_frame_bytes = %d, want %d", lim.GetMaxFrameBytes(), MaxFrameBytes)
	}
	if lim.GetDefaultMethodPayloadBytes() != defaultMethodPayloadBytes {
		t.Fatalf("default_method_payload_bytes = %d, want %d",
			lim.GetDefaultMethodPayloadBytes(), defaultMethodPayloadBytes)
	}
	wantIdle := uint32(DefaultLimits().IdleTimeout / time.Millisecond)
	if lim.GetIdleTimeoutMs() != wantIdle {
		t.Fatalf("idle_timeout_ms = %d, want %d", lim.GetIdleTimeoutMs(), wantIdle)
	}

	// 握手后 Ping→Pong
	if err := WriteFrame(c, mustMarshal(t, pingEnv(99))); err != nil {
		t.Fatal(err)
	}
	if got := readEnv(t, c).GetPong().GetNonce(); got != 99 {
		t.Fatalf("pong nonce = %d, want 99", got)
	}
}

// 第一帧不是 Hello：非法握手状态，直接关闭并审计为协议违规（不回 HelloAck）
func TestHandshake_FirstFrameNotHelloClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	// 一个良构但非 Hello 的帧
	if err := WriteFrame(c, mustMarshal(t, pingEnv(1))); err != nil {
		t.Fatal(err)
	}

	expectClosed(t, c)
	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })
	waitFor(t, "握手违规被审计",
		hasAudit(rec, "ipc.ProtocolViolation", errHandshakeExpectedHello))
}

// 版本谈不拢：先发 Failure HelloAck（FAILED_PRECONDITION）再关闭，不裸关，
// 好让客户端把「版本不兼容」与「socket 坏了」区分开
func TestHandshake_VersionMismatchSendsFailureThenCloses(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	// 客户端只支持 major 2，与 nervud 的 major 1 无交集
	bad := &ipcv1.Envelope{Body: &ipcv1.Envelope_Hello{Hello: &ipcv1.Hello{
		MinProtocolMajor: 2, MaxProtocolMajor: 2, MaxProtocolMinor: 0,
	}}}
	if err := WriteFrame(c, mustMarshal(t, bad)); err != nil {
		t.Fatal(err)
	}

	ack := readEnv(t, c).GetHelloAck()
	if ack == nil || ack.GetFailure() == nil {
		t.Fatalf("want Failure HelloAck, got %+v", ack)
	}
	if code := ack.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("failure code = %v, want FAILED_PRECONDITION", code)
	}
	// Failure 之后必须关闭
	expectClosed(t, c)
	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })
}

// 客户端 max major 高于 nervud：nervud 选自己的 major，minor 取自己的上限
func TestHandshake_ClientSupportsHigherMajor(t *testing.T) {
	inv := selfUIDInvariants(t)
	_, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	hi := &ipcv1.Envelope{Body: &ipcv1.Envelope_Hello{Hello: &ipcv1.Hello{
		MinProtocolMajor: 1, MaxProtocolMajor: 9, MaxProtocolMinor: 7,
	}}}
	if err := WriteFrame(c, mustMarshal(t, hi)); err != nil {
		t.Fatal(err)
	}
	s := readEnv(t, c).GetHelloAck().GetSuccess()
	if s == nil {
		t.Fatal("want success HelloAck")
	}
	if s.GetProtocolMajor() != protocolMajor || s.GetProtocolMinor() != protocolMinorMax {
		t.Fatalf("协商 = %d.%d, want %d.%d",
			s.GetProtocolMajor(), s.GetProtocolMinor(), protocolMajor, protocolMinorMax)
	}
}

// --- 握手后分派 -----------------------------------------------------------

// 握手后再来一个 Hello：非法握手状态，关闭并审计
func TestReady_DuplicateHelloClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	if err := WriteFrame(c, mustMarshal(t, helloEnv())); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })
	waitFor(t, "重复 Hello 被审计",
		hasAudit(rec, "ipc.ProtocolViolation", errDuplicateHello))
}

// Request 尚无 handler：回一个以 request_id 归位的 UNAVAILABLE Response，
// 不静默丢也不裸关
func TestReady_RequestReturnsUnavailable(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{
		RequestId: 7, EndpointId: 1, MethodId: 2,
	}}}
	if err := WriteFrame(c, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}

	resp := readEnv(t, c).GetResponse()
	if resp == nil {
		t.Fatal("want Response")
	}
	if resp.GetRequestId() != 7 {
		t.Fatalf("response request_id = %d, want 7", resp.GetRequestId())
	}
	if resp.GetSuccess() != nil {
		t.Fatal("未实现的 Request 不该回 success")
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("failure code = %v, want UNAVAILABLE", code)
	}
	// Response 之后连接仍存活（不是终结整条连接）
	if n := s.connCount(); n != 1 {
		t.Fatalf("回 UNAVAILABLE 不该关连接，connCount=%d", n)
	}
}

// 客户端发来只应由服务端产生的 body（此处用 Response）：协议违规，关闭并审计
func TestReady_ServerOriginatedBodyClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	srv := &ipcv1.Envelope{Body: &ipcv1.Envelope_Response{Response: &ipcv1.Response{RequestId: 1}}}
	if err := WriteFrame(c, mustMarshal(t, srv)); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })
	waitFor(t, "非法入站 body 被审计",
		hasAudit(rec, "ipc.ProtocolViolation", errUnexpectedBody))
}

// 客户端合法但本 build 未实现的 body（此处用 ResolveEndpoint）：关闭并审计为
// UnsupportedBody（区别于协议违规）
func TestReady_UnsupportedBodyClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	re := &ipcv1.Envelope{Body: &ipcv1.Envelope_ResolveEndpoint{ResolveEndpoint: &ipcv1.ResolveEndpoint{}}}
	if err := WriteFrame(c, mustMarshal(t, re)); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })
	waitFor(t, "未实现 body 被审计为 UnsupportedBody",
		hasAudit(rec, "ipc.UnsupportedBody", errUnsupportedBody))
}

// --- 版本协商（纯函数） ----------------------------------------------------

func TestNegotiateVersion(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		min, max, maxMinor   uint32
		wantMajor, wantMinor uint32
		wantOK               bool
	}{
		{"精确匹配", 1, 1, 0, 1, 0, true},
		{"客户端 minor 上限更高被裁到我们的上限", 1, 1, 5, 1, 0, true},
		{"客户端 max major 更高则用我们的 major 和 minor 上限", 1, 3, 9, 1, 0, true},
		{"min 为 0 也覆盖我们的 major", 0, 1, 0, 1, 0, true},
		{"整段高于我们的 major", 2, 2, 0, 0, 0, false},
		{"整段低于我们的 major", 0, 0, 0, 0, 0, false},
		{"颠倒范围（max<min）无交集", 1, 0, 0, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &ipcv1.Hello{
				MinProtocolMajor: tc.min, MaxProtocolMajor: tc.max, MaxProtocolMinor: tc.maxMinor,
			}
			major, minor, ok := negotiateVersion(h)
			if ok != tc.wantOK || major != tc.wantMajor || minor != tc.wantMinor {
				t.Fatalf("negotiateVersion = (%d,%d,%v), want (%d,%d,%v)",
					major, minor, ok, tc.wantMajor, tc.wantMinor, tc.wantOK)
			}
		})
	}
}
