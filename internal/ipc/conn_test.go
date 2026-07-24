package ipc

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/permission"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
)

func helloEnv() *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_Hello{Hello: &ipcv1.Hello{
		MinProtocolMajor: protocolMajor,
		MaxProtocolMajor: protocolMajor,
		MaxProtocolMinor: protocolMinorMax,
		SdkName:          "test",
		SdkVersion:       "0",
	}}}
}

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
		t.Fatal("HelloAck contains neither success nor failure")
	}
	return s
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF because the server should close the connection", err)
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

func TestHandshake_Success(t *testing.T) {
	inv := selfUIDInvariants(t)
	_, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	ack := handshake(t, c)

	if ack.GetProtocolMajor() != protocolMajor || ack.GetProtocolMinor() != protocolMinorMax {
		t.Fatalf("negotiated version = %d.%d, want %d.%d",
			ack.GetProtocolMajor(), ack.GetProtocolMinor(), protocolMajor, protocolMinorMax)
	}
	if ack.GetPackageId() != "com.nervus.test" {
		t.Fatalf("package_id = %q, want com.nervus.test", ack.GetPackageId())
	}
	if ack.GetComponentId() != "" {
		t.Fatalf("component_id = %q, want empty because an unverified self-reported value must not be echoed", ack.GetComponentId())
	}

	lim := ack.GetLimits()
	if lim == nil {
		t.Fatal("HelloAck did not include ConnectionLimits")
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
	for _, f := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"max_inflight_requests", uint64(lim.GetMaxInflightRequests()), maxInflightRequests},
		{"max_inflight_payload_bytes", lim.GetMaxInflightPayloadBytes(), maxInflightPayloadBytes},
		{"max_outbound_queue_bytes", lim.GetMaxOutboundQueueBytes(), maxOutboundQueueBytes},
		{"max_subscriptions", uint64(lim.GetMaxSubscriptions()), maxSubscriptions},
		{"default_timeout_ms", uint64(lim.GetDefaultTimeoutMs()), defaultMethodTimeoutMs},
		{"max_timeout_ms", uint64(lim.GetMaxTimeoutMs()), maxMethodTimeoutMs},
	} {
		if f.got != f.want {
			t.Fatalf("%s = %d, want %d", f.name, f.got, f.want)
		}
	}

	if err := WriteFrame(c, mustMarshal(t, pingEnv(99))); err != nil {
		t.Fatal(err)
	}
	if got := readEnv(t, c).GetPong().GetNonce(); got != 99 {
		t.Fatalf("pong nonce = %d, want 99", got)
	}
}

func TestHandshake_FirstFrameNotHelloClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	if err := WriteFrame(c, mustMarshal(t, pingEnv(1))); err != nil {
		t.Fatal(err)
	}

	expectClosed(t, c)
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
	waitFor(t, "handshake violation audit",
		hasAudit(rec, "ipc.ProtocolViolation", errHandshakeExpectedHello))
}

func TestHandshake_VersionMismatchSendsFailureThenCloses(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
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
	expectClosed(t, c)
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
}

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
		t.Fatalf("negotiated version = %d.%d, want %d.%d",
			s.GetProtocolMajor(), s.GetProtocolMinor(), protocolMajor, protocolMinorMax)
	}
}

func TestHandshake_FailsClosedWhenComponentUnverifiable(t *testing.T) {
	inv := selfUIDInvariants(t)
	sock := filepath.Join(t.TempDir(), "nervud.sock")
	s, err := New(Config{
		SockPath: sock, Log: discardLog(), Auditor: &fakeRecorder{},
		Invariants: inv, Identity: selfRegistry(t),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	})

	c := dial(t, sock)
	if err := WriteFrame(c, mustMarshal(t, helloEnv())); err != nil {
		t.Fatal(err)
	}
	ack := readEnv(t, c).GetHelloAck()
	if ack == nil || ack.GetFailure() == nil {
		t.Fatalf("want Failure HelloAck, got %+v", ack)
	}
	if code := ack.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED {
		t.Fatalf("failure code = %v, want UNAUTHENTICATED", code)
	}
	expectClosed(t, c)
}

func TestReady_DuplicateHelloClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	if err := WriteFrame(c, mustMarshal(t, helloEnv())); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
	waitFor(t, "duplicate Hello audit",
		hasAudit(rec, "ipc.ProtocolViolation", errDuplicateHello))
}

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
		t.Fatal("an unimplemented Request must not return success")
	}
	if code := resp.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("failure code = %v, want UNAVAILABLE", code)
	}
	if n := s.connCount(); n != 1 {
		t.Fatalf("returning UNAVAILABLE should not close the connection, connCount=%d", n)
	}
}

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
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
	waitFor(t, "invalid inbound body audit",
		hasAudit(rec, "ipc.ProtocolViolation", errUnexpectedBody))
}

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
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
	waitFor(t, "unsupported body audit",
		hasAudit(rec, "ipc.UnsupportedBody", errUnsupportedBody))
}

func TestReady_PongAccepted(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	pong := &ipcv1.Envelope{Body: &ipcv1.Envelope_Pong{Pong: &ipcv1.Pong{Nonce: 5}}}
	if err := WriteFrame(c, mustMarshal(t, pong)); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(c, mustMarshal(t, pingEnv(6))); err != nil {
		t.Fatal(err)
	}
	if got := readEnv(t, c).GetPong().GetNonce(); got != 6 {
		t.Fatalf("pong nonce = %d, want 6", got)
	}
	if n := s.connCount(); n != 1 {
		t.Fatalf("Pong should not close the connection, connCount=%d", n)
	}
}

func TestReady_DispatchIsProtocolViolation(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	d := &ipcv1.Envelope{Body: &ipcv1.Envelope_Dispatch{Dispatch: &ipcv1.Dispatch{RouteId: 1}}}
	if err := WriteFrame(c, mustMarshal(t, d)); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
	waitFor(t, "Dispatch protocol violation audit",
		hasAudit(rec, "ipc.ProtocolViolation", errUnexpectedBody))
}

func TestReady_UnmatchedDispatchResultIsDiscardedNotClosed(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	dr := &ipcv1.Envelope{Body: &ipcv1.Envelope_DispatchResult{DispatchResult: &ipcv1.DispatchResult{RouteId: 999}}}
	if err := WriteFrame(c, mustMarshal(t, dr)); err != nil {
		t.Fatal(err)
	}

	if err := WriteFrame(c, mustMarshal(t, pingEnv(1))); err != nil {
		t.Fatal(err)
	}
	if got := readEnv(t, c).GetPong().GetNonce(); got != 1 {
		t.Fatalf("pong nonce = %d, want 1", got)
	}
	if n := s.connCount(); n != 1 {
		t.Fatalf("an unknown DispatchResult should not close the connection, connCount=%d", n)
	}
	waitFor(t, "unknown route_id audit as DispatchResultUnmatched",
		hasAudit(rec, "ipc.DispatchResultUnmatched", nil))
}

func TestReady_RequestZeroIDIsViolation(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	req := &ipcv1.Envelope{Body: &ipcv1.Envelope_Request{Request: &ipcv1.Request{RequestId: 0}}}
	if err := WriteFrame(c, mustMarshal(t, req)); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c)
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
	waitFor(t, "request_id 0 protocol violation audit",
		hasAudit(rec, "ipc.ProtocolViolation", errZeroRequestID))
}

func TestNegotiateVersion(t *testing.T) {
	const srvMajor, srvMinorMax = 1, 3
	for _, tc := range []struct {
		name                 string
		min, max, maxMinor   uint32
		wantMajor, wantMinor uint32
		wantOK               bool
	}{
		{"exact match with client minor 0", 1, 1, 0, 1, 0, true},
		{"same major uses the lower client minor", 1, 1, 2, 1, 2, true},
		{"same major caps a higher client minor at the server maximum", 1, 1, 5, 1, 3, true},
		{"lower selected major uses guaranteed minor 0 instead of the server maximum", 1, 3, 9, 1, 0, true},
		{"minimum major 0 still covers the server major", 0, 1, 1, 1, 1, true},
		{"entire range above the server major", 2, 2, 0, 0, 0, false},
		{"entire range below the server major", 0, 0, 0, 0, 0, false},
		{"reversed range has no intersection", 1, 0, 0, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &ipcv1.Hello{
				MinProtocolMajor: tc.min, MaxProtocolMajor: tc.max, MaxProtocolMinor: tc.maxMinor,
			}
			major, minor, ok := negotiateVersion(h, srvMajor, srvMinorMax)
			if ok != tc.wantOK || major != tc.wantMajor || minor != tc.wantMinor {
				t.Fatalf("negotiateVersion = (%d,%d,%v), want (%d,%d,%v)",
					major, minor, ok, tc.wantMajor, tc.wantMinor, tc.wantOK)
			}
		})
	}
}
