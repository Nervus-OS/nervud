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

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
)

// fakeRecorder 捕获审计事件，供断言「该审计的都审计了」
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

// selfUIDInvariants 让当前测试进程的 UID 落在 App 区段内。
//
// DefaultInvariants 的区段是 [20000,59999]，而测试进程通常是 1000，
// 用默认值的话每条连接都会在准入处被拒，测不到后面的路径
func selfUIDInvariants(t *testing.T) *authority.Invariants {
	t.Helper()
	uid := uint32(os.Getuid())
	if uid == 0 {
		// CheckUID 无条件拒绝 UID 0（架构 5：App UID 0 永远禁止），
		// 以 root 运行时这些用例没有意义
		t.Skip("以 root 运行；准入用例需要一个非 0 的 UID")
	}
	return &authority.Invariants{
		DataRoot:    "/var/lib/nervus/data",
		PackageRoot: "/var/lib/nervus/packages",
		MinAppUID:   uid,
		MaxAppUID:   uid,
	}
}

// selfRegistry 返回一个把当前测试进程 UID 登记成合法 Package 的索引。
// 与 selfUIDInvariants 配套：一个让 UID 过区段检查，一个让它查得到 Package
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

// newTestServer 在 Linux 原生临时目录下建一个已启动的 Server。
// 不能用仓库所在目录：Windows 挂载点（DrvFs）不支持 Unix socket
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
		SockPath:   sock,
		Log:        discardLog(),
		Auditor:    rec,
		Invariants: inv,
		Identity:   id,
		Limits:     lim,
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

// newUnstartedServer 构造一个未 Start 的 Server（默认 Registry，空身份索引）。
// 供单例锁用例手动控制 Start/Stop 时机
func newUnstartedServer(t *testing.T, sock string, inv *authority.Invariants) *Server {
	t.Helper()
	s, err := New(Config{
		SockPath: sock, Log: discardLog(), Auditor: &fakeRecorder{},
		Invariants: inv, Identity: identity.NewRegistry(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// pingEnv 构造一个合法的 Ping Envelope，用于需要 良构帧 的用例
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

// waitFor 轮询直到 cond 成立或超时。用于等待服务端的异步状态收敛，
// 比固定 sleep 更快也更不容易在慢机器上偶发失败
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("超时等待：%s", what)
}

func (s *Server) connCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// --- 构造校验 -------------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	base := Config{
		SockPath:   "/run/nervus/nervud.sock",
		Log:        discardLog(),
		Auditor:    &fakeRecorder{},
		Invariants: authority.DefaultInvariants(),
		Identity:   identity.NewRegistry(),
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"缺 SockPath", func(c *Config) { c.SockPath = "" }},
		{"SockPath 非绝对路径", func(c *Config) { c.SockPath = "nervud.sock" }},
		{"缺 Log", func(c *Config) { c.Log = nil }},
		{"缺 Auditor", func(c *Config) { c.Auditor = nil }},
		{"缺 Invariants", func(c *Config) { c.Invariants = nil }},
		{"缺 Identity", func(c *Config) { c.Identity = nil }},
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

// 部分填写的 Limits 必须逐字段兜底：只设一个字段不该让其余字段落到零值
// （HandshakeTimeout=0 会让每条连接一建就超时断开，表现为 监听成功但没人连得上）
func TestNew_PartialLimitsGetPerFieldDefaults(t *testing.T) {
	s, err := New(Config{
		SockPath: "/run/nervus/nervud.sock", Log: discardLog(),
		Auditor: &fakeRecorder{}, Invariants: authority.DefaultInvariants(),
		Identity: identity.NewRegistry(),
		Limits:   Limits{MaxConns: 10}, // 只设一个字段
	})
	if err != nil {
		t.Fatal(err)
	}
	d := DefaultLimits()
	if s.limits.MaxConns != 10 {
		t.Fatalf("显式设的 MaxConns 被覆盖: %d", s.limits.MaxConns)
	}
	if s.limits.HandshakeTimeout != d.HandshakeTimeout ||
		s.limits.IdleTimeout != d.IdleTimeout ||
		s.limits.FrameBodyTimeout != d.FrameBodyTimeout ||
		s.limits.MaxConnsPerUID != d.MaxConnsPerUID ||
		s.limits.MaxFramesPerConnPerSec != d.MaxFramesPerConnPerSec {
		t.Fatalf("部分字段没有兜底到默认: %+v", s.limits)
	}
}

func TestNew_ZeroLimitsGetsDefaults(t *testing.T) {
	s, err := New(Config{
		SockPath:   "/run/nervus/nervud.sock",
		Log:        discardLog(),
		Auditor:    &fakeRecorder{},
		Invariants: authority.DefaultInvariants(),
		Identity:   identity.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.limits != DefaultLimits() {
		t.Fatalf("limits = %+v, want DefaultLimits()", s.limits)
	}
}

// --- socket 文件 ----------------------------------------------------------

func TestStart_SocketModeIsExplicit(t *testing.T) {
	_, sock, _ := newTestServer(t, authority.DefaultInvariants(), DefaultLimits())

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s 不是 socket，mode=%s", sock, fi.Mode())
	}
	// bind 时的权限受 umask 削减，必须由显式 chmod 覆盖回来。
	// 这条锁的就是那次 chmod 没被漏掉
	if got := fi.Mode().Perm(); got != socketMode.Perm() {
		t.Fatalf("perm = %o, want %o（umask 削减后没有被 chmod 改回来？）", got, socketMode.Perm())
	}
}

func TestStart_RemovesStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nervud.sock")

	// 造一个残骸：监听后关闭且不 unlink，模拟上一次运行被 SIGKILL
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("残骸没造出来: %v", err)
	}

	s, err := New(Config{
		SockPath: sock, Log: discardLog(), Auditor: &fakeRecorder{},
		Invariants: authority.DefaultInvariants(), Identity: identity.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start 应当清理残骸后成功，却失败了: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.Stop(ctx)
}

// 另一个实例还活着时必须拒绝启动，绝不能把它的 socket 抢过来——
// 那会让两个内核同时认为自己拥有控制面。由 abstract 单例锁的 bind 原子性保证
func TestStart_RefusesWhenAnotherInstanceIsLive(t *testing.T) {
	_, sock, _ := newTestServer(t, authority.DefaultInvariants(), DefaultLimits())

	second := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := second.Start(context.Background()); err == nil {
		t.Fatal("第二个实例不该启动成功")
	}
	// 而且第一个实例必须仍然可用
	dial(t, sock)
}

// 单例锁必须在 Stop 后释放：同一 sockPath 关掉旧实例后能重新起一个新实例。
// abstract socket 关闭即由内核回收，不留残骸
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

	// 锁应已释放：第二个实例（同路径）必须能起来
	second := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := second.Start(context.Background()); err != nil {
		t.Fatalf("锁没有在 Stop 后释放，新实例起不来: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_ = second.Stop(ctx2)
}

// Start 在拿到锁之后失败，必须把锁还回去——否则同一 sockPath 再也起不来。
// 用 非 socket 文件 触发一次 拿锁之后 的失败，然后验证同路径能重新启动
func TestStart_SingletonLockReleasedOnStartFailure(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nervud.sock")
	if err := os.WriteFile(sock, []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}

	failing := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := failing.Start(context.Background()); err == nil {
		t.Fatal("非 socket 路径应导致 Start 失败")
	}

	// 换掉那个非 socket 文件，同一路径必须能起来——证明失败路径已释放锁
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	ok := newUnstartedServer(t, sock, authority.DefaultInvariants())
	if err := ok.Start(context.Background()); err != nil {
		t.Fatalf("Start 失败路径没有释放锁: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = ok.Stop(ctx)
}

// 路径存在但不是 socket 时拒绝而不是删除：在固定路径上盲删任意文件不可逆
func TestStart_RefusesNonSocketFile(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nervud.sock")
	if err := os.WriteFile(sock, []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New(Config{
		SockPath: sock, Log: discardLog(), Auditor: &fakeRecorder{},
		Invariants: authority.DefaultInvariants(), Identity: identity.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("want error for non-socket path")
	}
	// 文件必须原封不动
	b, err := os.ReadFile(sock)
	if err != nil || string(b) != "important" {
		t.Fatalf("原文件被破坏了: %q, err=%v", b, err)
	}
}

func TestStart_Twice(t *testing.T) {
	s, _, _ := newTestServer(t, authority.DefaultInvariants(), DefaultLimits())
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("重复 Start 应当报错")
	}
}

// --- 准入 -----------------------------------------------------------------

func TestAdmit_AcceptsInRangeUID(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	dial(t, sock)
	waitFor(t, "连接被登记", func() bool { return s.connCount() == 1 })
}

// UID 不在 App 区段内必须被拒，且拒绝要落审计
func TestAdmit_RejectsOutOfRangeUID(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("以 root 运行")
	}
	// 故意把区段设成不含当前 UID
	inv := &authority.Invariants{
		DataRoot: "/var/lib/nervus/data", PackageRoot: "/var/lib/nervus/packages",
		MinAppUID: 20000, MaxAppUID: 59999,
	}
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	// 服务端会立刻关闭，客户端读到 EOF
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF（服务端应当直接关闭）", err)
	}
	if n := s.connCount(); n != 0 {
		t.Fatalf("被拒的连接不该被登记，connCount=%d", n)
	}

	waitFor(t, "拒绝被审计", func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Action == "ipc.ConnectionRejected" && ev.Denied {
				return true
			}
		}
		return false
	})
}

// UID 落在 App 区段内不代表它属于某个已注册 Package：手工创建的系统用户、
// 或者 Package 已卸载而进程还活着，都必须被拒
//
// 这条与 TestAdmit_RejectsOutOfRangeUID 是两道不同的关卡，一起测才能确认
// 身份解析确实接在区段检查后面，而不是被区段检查顺带挡掉了
func TestAdmit_RejectsUnregisteredUID(t *testing.T) {
	inv := selfUIDInvariants(t)
	// 空索引：当前 UID 过得了区段检查，但查不到任何 Package
	s, sock, rec := newTestServerWith(t, inv, identity.NewRegistry(), DefaultLimits())

	c := dial(t, sock)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF（服务端应当直接关闭）", err)
	}
	if n := s.connCount(); n != 0 {
		t.Fatalf("被拒的连接不该被登记，connCount=%d", n)
	}

	waitFor(t, "拒绝被审计", func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Action == "ipc.ConnectionRejected" &&
				errors.Is(ev.Err, identity.ErrUnknownUID) {
				return true
			}
		}
		return false
	})
}

// 每 UID 连接数上限：超出的连接必须被拒，且不影响已建立的连接
func TestAdmit_PerUIDConnectionLimit(t *testing.T) {
	inv := selfUIDInvariants(t)
	lim := DefaultLimits()
	lim.MaxConnsPerUID = 2
	s, sock, _ := newTestServer(t, inv, lim)

	dial(t, sock)
	dial(t, sock)
	waitFor(t, "两条连接都被登记", func() bool { return s.connCount() == 2 })

	third := dial(t, sock)
	_ = third.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := third.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("第三条连接 read err = %v, want io.EOF", err)
	}
	if n := s.connCount(); n != 2 {
		t.Fatalf("connCount = %d, want 2", n)
	}
}

// 连接关闭后额度必须归还，否则 perUID 计数只增不减，该 UID 会被永久锁死
func TestAdmit_ReleasesQuotaOnClose(t *testing.T) {
	inv := selfUIDInvariants(t)
	lim := DefaultLimits()
	lim.MaxConnsPerUID = 1
	s, sock, _ := newTestServer(t, inv, lim)

	first, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "第一条连接被登记", func() bool { return s.connCount() == 1 })

	_ = first.Close()
	waitFor(t, "额度被归还", func() bool { return s.connCount() == 0 })

	// 额度归还后必须能再连上
	dial(t, sock)
	waitFor(t, "新连接被登记", func() bool { return s.connCount() == 1 })
}

// --- 帧处理 ---------------------------------------------------------------

func TestServe_ValidEnvelopeKeepsConnectionOpen(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	env := &ipcv1.Envelope{Body: &ipcv1.Envelope_Ping{Ping: &ipcv1.Ping{Nonce: 1}}}
	if err := WriteFrame(c, mustMarshal(t, env)); err != nil {
		t.Fatal(err)
	}
	// 连接应当保持存活（当前实现解出 Envelope 后尚未分派，但不关连接）
	time.Sleep(50 * time.Millisecond)
	if n := s.connCount(); n != 1 {
		t.Fatalf("合法 Envelope 不该导致断开，connCount=%d", n)
	}
}

// 帧边界合法但正文不是 Envelope：属于协议违规，必须断开并审计。
// 这条走真实 socket，验证 parseEnvelope 确实接在帧泵里而不只是单测里能过
func TestServe_MalformedEnvelopeClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	// 0x08 是 field 1 varint 的 tag，缺正文 —— 截断的 wire 数据
	if err := WriteFrame(c, []byte{0x08}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })
	waitFor(t, "协议违规被审计且能归因到 Package/UID", func() bool {
		for _, ev := range rec.snapshot() {
			// Subject 必须被填上（之前是空的，无法归因）
			if ev.Action == "ipc.ProtocolViolation" && ev.Subject != "" && ev.Subject != "kernel" {
				return true
			}
		}
		return false
	})
}

// 连接建立后 Package 被卸载/降权：下一帧到来时服务端每帧复核发现身份已变，
// 立即断开。挡住 review 指出的 客户端持续发合法帧即可无限续命
func TestServe_RevokedIdentityClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	reg := selfRegistry(t)
	s, sock, rec := newTestServerWith(t, inv, reg, DefaultLimits())

	c := dial(t, sock)
	// 第一帧：身份仍在，连接正常
	if err := WriteFrame(c, mustMarshal(t, pingEnv(1))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "首帧后连接存活", func() bool { return s.connCount() == 1 })

	// 撤销身份：把 Package 从 Registry 移除（模拟卸载）
	if err := reg.Replace(nil); err != nil {
		t.Fatal(err)
	}

	// 第二帧：服务端复核发现身份没了 -> 关连接
	_ = WriteFrame(c, mustMarshal(t, pingEnv(2)))
	waitFor(t, "撤权后连接被回收", func() bool { return s.connCount() == 0 })
	waitFor(t, "撤权被审计", func() bool {
		for _, ev := range rec.snapshot() {
			if errors.Is(ev.Err, errIdentityRevoked) {
				return true
			}
		}
		return false
	})
}

// 单连接入站帧速率超限即关连接：挡住死循环刷帧造成的持续 CPU/GC 压力
func TestServe_FrameRateCapClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	lim := DefaultLimits()
	lim.MaxFramesPerConnPerSec = 5
	s, sock, rec := newTestServerWith(t, inv, selfRegistry(t), lim)

	c := dial(t, sock)
	frame := mustMarshal(t, pingEnv(1))
	for range 50 { // 远多于 5
		if err := WriteFrame(c, frame); err != nil {
			break // 服务端已关连接，写会失败
		}
	}

	waitFor(t, "超速连接被回收", func() bool { return s.connCount() == 0 })
	waitFor(t, "超速被审计", func() bool {
		for _, ev := range rec.snapshot() {
			if errors.Is(ev.Err, errFrameRateExceeded) {
				return true
			}
		}
		return false
	})
}

// 超限长度必须立刻断开，且服务端不能去排空攻击者自称的正文
func TestServe_OversizeFrameClosesConnection(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, rec := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	// 只发长度前缀，正文一个字节都不给
	if _, err := c.Write(hdr(MaxFrameBytes + 1)); err != nil {
		t.Fatal(err)
	}

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read err = %v, want io.EOF", err)
	}
	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })

	waitFor(t, "协议违规被审计", func() bool {
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
	waitFor(t, "连接被回收", func() bool { return s.connCount() == 0 })
}

// 只发长度不发正文（slowloris）：正文 deadline 必须把连接掐掉。
// 这条同时锁住「正文 deadline 显著短于空闲 deadline」这个设计——
// 若两者被合并成一个，本用例会跑满 IdleTimeout 才结束
func TestServe_SlowlorisHitsBodyDeadline(t *testing.T) {
	inv := selfUIDInvariants(t)
	lim := DefaultLimits()
	lim.FrameBodyTimeout = 150 * time.Millisecond
	lim.IdleTimeout = 30 * time.Second
	s, sock, _ := newTestServer(t, inv, lim)

	c := dial(t, sock)
	// 宣告 1000 字节，只给 1 字节，然后什么都不做
	if _, err := c.Write(append(hdr(1000), 'x')); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	waitFor(t, "正文 deadline 掐断连接", func() bool { return s.connCount() == 0 })
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("耗时 %v，说明用的是 IdleTimeout 而不是 FrameBodyTimeout", elapsed)
	}
}

// --- 停机 -----------------------------------------------------------------

func TestStop_ClosesLiveConnectionsAndUnlinks(t *testing.T) {
	inv := selfUIDInvariants(t)
	s, sock, _ := newTestServer(t, inv, DefaultLimits())

	c := dial(t, sock)
	waitFor(t, "连接被登记", func() bool { return s.connCount() == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// 存活连接必须被强制关闭，否则阻塞在 Read 的 goroutine 永远不退出
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("Stop 后连接仍可读，说明没有被强制关闭")
	}

	// socket 文件必须被 unlink，否则下次启动要走残骸清理路径
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket 文件未被删除: err=%v", err)
	}
}

// Stop 必须幂等：Kernel 回滚路径可能对同一模块调用多次
func TestStop_Idempotent(t *testing.T) {
	s, _, _ := newTestServer(t, authority.DefaultInvariants(), DefaultLimits())
	ctx := context.Background()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("第一次 Stop: %v", err)
	}
	// 第二次会因监听已关闭而返回错误，但绝不能 panic（close of closed channel）
	_ = s.Stop(ctx)
}
