package ipc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
)

type fakeRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeRecorder) Record(_ context.Context, ev audit.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeRecorder) snapshot() []audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Event(nil), f.events...)
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func selfUIDInvariants(t *testing.T) *authority.Invariants {
	t.Helper()
	uid := uint32(os.Getuid())
	if uid == 0 {
		t.Skip("running as root; admission tests require a nonzero UID")
	}
	return &authority.Invariants{
		DataRoot:    "/var/lib/nervus/package-data",
		PackageRoot: "/var/lib/nervus/packages",
		MinAppUID:   uid,
		MaxAppUID:   uid,
	}
}

func selfRegistry(t *testing.T) *identity.Registry {
	t.Helper()
	r := identity.NewRegistry()
	err := r.Replace([]identity.Package{{
		ID: "com.nervus.test", UID: uint32(os.Getuid()), Trust: identity.TrustOrdinary,
	}})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	return r
}

func newTestServer(t *testing.T, inv *authority.Invariants, lim Limits) (*Server, string, *fakeRecorder) {
	t.Helper()
	return newTestServerWith(t, inv, selfRegistry(t), lim)
}

func newTestServerWith(
	t *testing.T, inv *authority.Invariants, id PeerResolver, lim Limits,
) (*Server, string, *fakeRecorder) {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "nervud.sock")
	rec := &fakeRecorder{}
	s, err := New(Config{
		SockPath:                 sock,
		Log:                      discardLog(),
		Auditor:                  rec,
		Invariants:               inv,
		Identity:                 id,
		Permission:               permission.NewRegistry(permission.DefaultCatalog()),
		Limits:                   lim,
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
	return s, sock, rec
}

func newUnstartedServer(t *testing.T, sock string, inv *authority.Invariants) *Server {
	t.Helper()
	s, err := New(Config{
		SockPath: sock, Log: discardLog(), Auditor: &fakeRecorder{},
		Invariants: inv, Identity: identity.NewRegistry(),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func pingEnv(nonce uint64) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_Ping{Ping: &ipcv1.Ping{Nonce: nonce}}}
}

func dial(t *testing.T, sock string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (s *Server) connCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func TestNew_Validation(t *testing.T) {
	base := Config{
		SockPath:   "/run/nervus/nervud.sock",
		Log:        discardLog(),
		Auditor:    &fakeRecorder{},
		Invariants: authority.DefaultInvariants(),
		Identity:   identity.NewRegistry(),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing SockPath", func(c *Config) { c.SockPath = "" }},
		{"relative SockPath", func(c *Config) { c.SockPath = "nervud.sock" }},
		{"missing Log", func(c *Config) { c.Log = nil }},
		{"missing Auditor", func(c *Config) { c.Auditor = nil }},
		{"missing Invariants", func(c *Config) { c.Invariants = nil }},
		{"missing Identity", func(c *Config) { c.Identity = nil }},
		{"missing Permission", func(c *Config) { c.Permission = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestNew_PartialLimitsGetPerFieldDefaults(t *testing.T) {
	s, err := New(Config{
		SockPath: "/run/nervus/nervud.sock", Log: discardLog(),
		Auditor: &fakeRecorder{}, Invariants: authority.DefaultInvariants(),
		Identity:   identity.NewRegistry(),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
		Limits:     Limits{MaxConns: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := DefaultLimits()
	if s.limits.MaxConns != 10 {
		t.Fatalf("explicit MaxConns was overwritten: %d", s.limits.MaxConns)
	}
	if s.limits.HandshakeTimeout != d.HandshakeTimeout ||
		s.limits.IdleTimeout != d.IdleTimeout ||
		s.limits.FrameBodyTimeout != d.FrameBodyTimeout ||
		s.limits.MaxConnsPerUID != d.MaxConnsPerUID ||
		s.limits.MaxFramesPerConnPerSec != d.MaxFramesPerConnPerSec {
		t.Fatalf("partially configured fields did not receive defaults: %+v", s.limits)
	}
}

func TestNew_ZeroLimitsGetsDefaults(t *testing.T) {
	s, err := New(Config{
		SockPath:   "/run/nervus/nervud.sock",
		Log:        discardLog(),
		Auditor:    &fakeRecorder{},
		Invariants: authority.DefaultInvariants(),
		Identity:   identity.NewRegistry(),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.limits != DefaultLimits() {
		t.Fatalf("limits = %+v, want DefaultLimits()", s.limits)
	}
}

func TestStart_SocketModeIsExplicit(t *testing.T) {
	_, sock, _ := newTestServer(t, authority.DefaultInvariants(), DefaultLimits())

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket, mode=%s", sock, fi.Mode())
	}
	if got := fi.Mode().Perm(); got != socketMode.Perm() {
		t.Fatalf("perm = %o, want %o; chmod did not restore permissions after umask", got, socketMode.Perm())
	}
}

func TestStart_RemovesStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nervud.sock")

	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("failed to create stale socket state: %v", err)
	}

	s, err := New(Config{
		SockPath: sock, Log: discardLog(), Auditor: &fakeRecorder{},
		Invariants: authority.DefaultInvariants(), Identity: identity.NewRegistry(),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start should remove stale state and succeed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.Stop(ctx)
}

func TestStart_RefusesWhenAnotherInstanceIsLive(t *testing.T) {
	_, sock, _ := newTestServer(t, authority.DefaultInvariants(), DefaultLimits())

	second := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := second.Start(context.Background()); err == nil {
		t.Fatal("a second instance should not start successfully")
	}
	dial(t, sock)
}

func TestStart_SingletonLockReleasedOnStop(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nervud.sock")

	first := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := first.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := first.Stop(ctx); err != nil {
		t.Fatalf("first Stop: %v", err)
	}

	second := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := second.Start(context.Background()); err != nil {
		t.Fatalf("lock was not released after Stop, so a new instance could not start: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_ = second.Stop(ctx2)
}

func TestStart_SingletonLockReleasedOnStartFailure(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nervud.sock")
	if err := os.WriteFile(sock, []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}

	failing := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := failing.Start(context.Background()); err == nil {
		t.Fatal("Start should fail when the path contains a non-socket")
	}

	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	ok := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := ok.Start(context.Background()); err != nil {
		t.Fatalf("the failed Start path did not release the lock: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = ok.Stop(ctx)
}

func TestStart_RefusesNonSocketFile(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nervud.sock")
	if err := os.WriteFile(sock, []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New(Config{
		SockPath: sock, Log: discardLog(), Auditor: &fakeRecorder{},
		Invariants: authority.DefaultInvariants(), Identity: identity.NewRegistry(),
		Permission: permission.NewRegistry(permission.DefaultCatalog()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("want error for non-socket path")
	}
	b, err := os.ReadFile(sock)
	if err != nil || string(b) != "important" {
		t.Fatalf("the existing file was damaged: %q, err=%v", b, err)
	}
}

func TestStart_Twice(t *testing.T) {
	s, _, _ := newTestServer(t, authority.DefaultInvariants(), DefaultLimits())
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("a duplicate Start should return an error")
	}
}

func TestAdmit_AcceptsInRangeUID(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	dial(t, sock)
	waitFor(t, "connection registration", func() bool { return s.connCount() == 1 })
}

func TestAdmit_RejectsOutOfRangeUID(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	inv := &authority.Invariants{
		DataRoot: "/var/lib/nervus/package-data", PackageRoot: "/var/lib/nervus/packages",
		MinAppUID: 20000, MaxAppUID: 59999,
	}
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF because the server should close immediately", err)
	}
	if n := s.connCount(); n != 0 {
		t.Fatalf("a rejected connection must not be registered, connCount=%d", n)
	}

	waitFor(t, "rejection audit", func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Action == "ipc.ConnectionRejected" && ev.Denied {
				return true
			}
		}
		return false
	})
}

func TestAdmit_RejectsUnregisteredUID(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServerWith(t, inv, identity.NewRegistry(), DefaultLimits())

	c := dial(t, sock)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF because the server should close immediately", err)
	}
	if n := s.connCount(); n != 0 {
		t.Fatalf("a rejected connection must not be registered, connCount=%d", n)
	}

	waitFor(t, "rejection audit", func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Action == "ipc.ConnectionRejected" &&
				errors.Is(ev.Err, identity.ErrUnknownUID) {
				return true
			}
		}
		return false
	})
}

func TestAdmit_PerUIDConnectionLimit(t *testing.T) {
	inv := selfUIDInvariants(t)
	lim := DefaultLimits()
	lim.MaxConnsPerUID = 2
	s, sock, _ := newTestServer(t, inv, lim)

	dial(t, sock)
	dial(t, sock)
	waitFor(t, "both connections to be registered", func() bool { return s.connCount() == 2 })

	third := dial(t, sock)
	_ = third.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := third.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("third connection read err = %v, want io.EOF", err)
	}
	if n := s.connCount(); n != 2 {
		t.Fatalf("connCount = %d, want 2", n)
	}
}

func TestAdmit_ReleasesQuotaOnClose(t *testing.T) {
	inv := selfUIDInvariants(t)
	lim := DefaultLimits()
	lim.MaxConnsPerUID = 1
	s, sock, _ := newTestServer(t, inv, lim)

	first, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first connection registration", func() bool { return s.connCount() == 1 })

	_ = first.Close()
	waitFor(t, "connection quota release", func() bool { return s.connCount() == 0 })

	dial(t, sock)
	waitFor(t, "new connection registration", func() bool { return s.connCount() == 1 })
}

func TestServe_ValidEnvelopeKeepsConnectionOpen(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	if err := WriteFrame(c, mustMarshal(t, pingEnv(1))); err != nil {
		t.Fatal(err)
	}
	if got := readEnv(t, c).GetPong().GetNonce(); got != 1 {
		t.Fatalf("pong nonce = %d, want 1", got)
	}
	if n := s.connCount(); n != 1 {
		t.Fatalf("Ping/Pong should not close the connection, connCount=%d", n)
	}
}

func TestServe_MalformedEnvelopeClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	if err := WriteFrame(c, []byte{0x08}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
	waitFor(t, "attributed protocol violation audit", func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Action == "ipc.ProtocolViolation" && ev.Subject != "" && ev.Subject != "kernel" {
				return true
			}
		}
		return false
	})
}

func TestServe_RevokedIdentityClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	reg := selfRegistry(t)
	s, sock, rec := newTestServerWith(t, inv, reg, DefaultLimits())

	c := dial(t, sock)
	handshake(t, c)

	if err := WriteFrame(c, mustMarshal(t, pingEnv(1))); err != nil {
		t.Fatal(err)
	}
	_ = readEnv(t, c) // Pong
	waitFor(t, "connection to remain alive after the first frame", func() bool { return s.connCount() == 1 })

	if err := reg.Replace(nil); err != nil {
		t.Fatal(err)
	}

	_ = WriteFrame(c, mustMarshal(t, pingEnv(2)))
	waitFor(t, "connection cleanup after revocation", func() bool { return s.connCount() == 0 })
	waitFor(t, "revocation audit", func() bool {
		for _, ev := range rec.snapshot() {
			if errors.Is(ev.Err, errIdentityRevoked) {
				return true
			}
		}
		return false
	})
}

func TestServe_FrameRateCapClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	lim := DefaultLimits()
	lim.MaxFramesPerConnPerSec = 5
	s, sock, rec := newTestServerWith(t, inv, selfRegistry(t), lim)

	c := dial(t, sock)
	if err := WriteFrame(c, mustMarshal(t, helloEnv())); err != nil {
		t.Fatal(err)
	}
	frame := mustMarshal(t, pingEnv(1))
	for range 50 {
		if err := WriteFrame(c, frame); err != nil {
			break
		}
	}

	waitFor(t, "rate-limited connection cleanup", func() bool { return s.connCount() == 0 })
	waitFor(t, "rate-limit audit", func() bool {
		for _, ev := range rec.snapshot() {
			if errors.Is(ev.Err, errFrameRateExceeded) {
				return true
			}
		}
		return false
	})
}

func TestServe_OversizeFrameClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	if _, err := c.Write(hdr(MaxFrameBytes + 1)); err != nil {
		t.Fatal(err)
	}

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF", err)
	}
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })

	waitFor(t, "protocol violation audit", func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Action == "ipc.ProtocolViolation" {
				return true
			}
		}
		return false
	})
}

func TestServe_ZeroLengthFrameClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	if _, err := c.Write(hdr(0)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "connection cleanup", func() bool { return s.connCount() == 0 })
}

func TestServe_SlowlorisHitsBodyDeadline(t *testing.T) {
	inv := selfUIDInvariants(t)
	lim := DefaultLimits()
	lim.FrameBodyTimeout = 150 * time.Millisecond
	lim.IdleTimeout = 30 * time.Second
	s, sock, _ := newTestServer(t, inv, lim)

	c := dial(t, sock)
	if _, err := c.Write(append(hdr(1000), 'x')); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	waitFor(t, "frame body deadline to close the connection", func() bool { return s.connCount() == 0 })
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("elapsed %v indicates IdleTimeout was used instead of FrameBodyTimeout", elapsed)
	}
}

func TestStop_ClosesLiveConnectionsAndUnlinks(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	waitFor(t, "connection registration", func() bool { return s.connCount() == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection remained readable after Stop, so it was not forcibly closed")
	}

	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket file was not removed: err=%v", err)
	}
}

func TestStop_Idempotent(t *testing.T) {
	s, _, _ := newTestServer(t, authority.DefaultInvariants(), DefaultLimits())
	ctx := context.Background()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	_ = s.Stop(ctx)
}
