// 本文件是 ipc 模块的 kernel.Module 实现：UDS 监听、accept 循环、连接准入与
// 有序停机。分帧见 frame.go；连接内的 Envelope 状态机见 conn.go（待落地）
//
// 依赖边界：本包不直接 import syscall / x/sys —— 读取对端凭证走 internal/sysprobe，
// 特权操作走 internal/authority
package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/sysprobe"
)

// socketMode 是控制面 socket 的文件权限
//
// 取 0666 而不是 0660 加专用组，是因为每个 Package 有各自独立的 UID（架构 9），
// 用组来表达谁是 App 会让组成员关系变成与 Package Registry 并行的第二个真相源：
// 装包时加组、卸载时移组，一旦失步就出现 Registry 说已卸载、组里还在、仍能连
// 上来。Registry 是唯一真相源，不给它制造竞争者
//
// 真正的鉴权在 accept 之后：SO_PEERCRED 拿内核凭证，App UID 区段检查，
// Registry 查表。文件位只是第一道噪音过滤，不承担安全职责
//
// 代价是任何本地进程都能 connect 并迫使 nervud 走一遍拒绝流程，由 Limits.MaxConns
// 的全局上限兜底。若日后实测该面确有压力，改成 0660 加组是一行的事，但那时组
// 只做加固，仍然不作为真相源
const socketMode fs.FileMode = 0o666

// Limits 是本模块用到的准入预算（架构 10.11）
//
// 只放当前真正被执行的项。in-flight 请求数、payload 字节、outbound 队列字节等
// 属于连接内的预算，等 Envelope 层落地时再加——提前定义一堆没人读的字段，只会
// 让人以为它们已经生效
type Limits struct {
	// MaxConns 是进程级并发连接上限。socket 是 0666，因此这是防止本地进程靠
	// 狂开连接耗尽 fd 与内存的最后一道
	MaxConns int

	// MaxConnsPerUID 限制单个 Package 能占的连接数，防止一个 UID 吃掉全局额度
	MaxConnsPerUID int

	// HandshakeTimeout 是从 accept 到收到第一帧的上限。没有它，连上不说话就能
	// 白占一个连接槽
	HandshakeTimeout time.Duration

	// IdleTimeout 是稳态下两个 Frame 之间允许的最长间隔，由 Ping/Pong 维持
	IdleTimeout time.Duration

	// FrameBodyTimeout 是读完一个已宣告长度的正文的上限
	//
	// 它必须显著短于 IdleTimeout：长度前缀一旦收到，就说明 N 字节已经在路上，
	// 再慢也该很快到齐。用 IdleTimeout 覆盖正文读取等于把空闲容忍度送给
	// slowloris——发完 4 字节头后每秒挤一个字节即可长期占住连接
	FrameBodyTimeout time.Duration

	// MaxFramesPerConnPerSec 是【单连接】入站帧速率上限（§10.11 的第一道）
	//
	// 每帧都要 proto.Unmarshal，一个死循环刷帧的合法 App 能持续制造 CPU/GC
	// 压力。本上限设得足够高，正常客户端（交互式几十/秒、高频遥测几百/秒）
	// 远够不着，只截断病理性的 tight loop。超限即按滥用关连接并审计
	//
	// 这只是第一道：完整的 §10.11 要求【每 UID 聚合】的字节速率 token bucket，
	// 且超限应返回 RESOURCE_EXHAUSTED 而非直接关连接——那需要 Envelope 层的
	// Response 能力，随 conn.go 落地
	MaxFramesPerConnPerSec int
}

// DefaultLimits 是架构 10.11 的固定取值
func DefaultLimits() Limits {
	return Limits{
		MaxConns:               256,
		MaxConnsPerUID:         4,
		HandshakeTimeout:       5 * time.Second,
		IdleTimeout:            60 * time.Second,
		FrameBodyTimeout:       5 * time.Second,
		MaxFramesPerConnPerSec: 2000,
	}
}

// normalizeLimits 对每个字段【逐一】填默认值
//
// 不能只在整个结构全零时才用默认：部分填写（只设了 MaxConns，其余留零）会让
// HandshakeTimeout=0 这类字段生效——SetReadDeadline(now) 立即超时，连接一建就
// 断，表现为 监听成功但谁都连不上，极难排查。逐字段兜底把这种半填配置也拉回安全
func normalizeLimits(l Limits) Limits {
	d := DefaultLimits()
	if l.MaxConns <= 0 {
		l.MaxConns = d.MaxConns
	}
	if l.MaxConnsPerUID <= 0 {
		l.MaxConnsPerUID = d.MaxConnsPerUID
	}
	if l.HandshakeTimeout <= 0 {
		l.HandshakeTimeout = d.HandshakeTimeout
	}
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = d.IdleTimeout
	}
	if l.FrameBodyTimeout <= 0 {
		l.FrameBodyTimeout = d.FrameBodyTimeout
	}
	if l.MaxFramesPerConnPerSec <= 0 {
		l.MaxFramesPerConnPerSec = d.MaxFramesPerConnPerSec
	}
	return l
}

type Config struct {
	// SockPath 是控制面入口，生产固定 /run/nervus/nervud.sock
	SockPath string

	Log     *slog.Logger
	Auditor audit.Recorder

	// Invariants 提供 App UID 区段检查。传值而不是传 *authority.Gate：
	// ipc 不需要任何特权操作，只需要那条不变量
	Invariants *authority.Invariants

	// Identity 把内核凭证映射成可信身份。接口由本包（消费者）定义，
	// *identity.Registry 隐式满足
	Identity PeerResolver

	// Limits 为零值时使用 DefaultLimits()
	Limits Limits
}

// PeerResolver 把 SO_PEERCRED 凭证解析成可信身份
//
// 接口在消费者这一侧定义，实现由 internal/identity 提供。ipc 只需要这一个
// 方法，没有理由持有整个 Registry —— 拿到全部方法的模块越少，
// 「谁能改身份索引」这个问题的答案就越短
type PeerResolver interface {
	Resolve(cred sysprobe.Ucred) (identity.Caller, error)
}

// Server 是控制面 UDS 的所有者
//
// 生命周期契约：Start 必须快速返回，后台循环的退出只听 Stop()，不听 Start(ctx)
// 的 ctx。若后台循环也监听信号 ctx，它会与 Kernel.stopAll 被同一个信号并行唤醒，
// 谁先退出不确定，停机顺序就不再由 Kernel 的反序 Stop 唯一决定
type Server struct {
	sockPath string
	log      *slog.Logger
	auditor  audit.Recorder
	inv      *authority.Invariants
	identity PeerResolver
	limits   Limits

	ln *net.UnixListener

	// lockLn 是单例锁：一个 abstract namespace socket，名字由 sockPath 派生。
	// 它从不 Accept，只靠占用 abstract 名字来保证同一时刻只有一个 nervud。
	// 见 acquireSingletonLock
	lockLn *net.UnixListener

	// quit 由 Stop 关闭，是全部后台 goroutine 的唯一退出信号
	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup

	// fatal 承载后台循环已经无法继续的错误，容量 1、只写一次
	fatal chan error

	mu      sync.Mutex
	conns   map[*net.UnixConn]struct{}
	perUID  map[uint32]int
	started bool

	// rejectLog 给准入拒绝路径的审计限速。被拒绝的连接可以由攻击者任意刷，
	// 不限速的话审计日志本身就成了放大器
	rejectLog rateLimiter

	// violationLog 给协议违规路径的审计限速。畸形帧同样可被恶意连接刷，
	// 与 rejectLog 同理需要限速
	violationLog rateLimiter
}

func New(cfg Config) (*Server, error) {
	if cfg.SockPath == "" {
		return nil, errors.New("ipc: SockPath is required")
	}
	if !filepath.IsAbs(cfg.SockPath) {
		// 相对路径的含义取决于进程 cwd，而 cwd 可被 systemd 单元或运行期 chdir
		// 改变，等于把控制面入口交给外部状态
		return nil, fmt.Errorf("ipc: SockPath %q must be absolute", cfg.SockPath)
	}
	if cfg.Log == nil {
		return nil, errors.New("ipc: Log is required")
	}
	if cfg.Auditor == nil {
		return nil, errors.New("ipc: Auditor is required")
	}
	if cfg.Invariants == nil {
		return nil, errors.New("ipc: Invariants is required")
	}
	if cfg.Identity == nil {
		// 不给默认实现：缺身份解析时唯一安全的默认是「谁都不认识」，
		// 那等于开着一个谁也连不上的 socket。装配阶段就该发现
		return nil, errors.New("ipc: Identity is required")
	}

	return &Server{
		sockPath:     cfg.SockPath,
		log:          cfg.Log,
		auditor:      cfg.Auditor,
		inv:          cfg.Invariants,
		identity:     cfg.Identity,
		limits:       normalizeLimits(cfg.Limits),
		quit:         make(chan struct{}),
		fatal:        make(chan error, 1),
		conns:        make(map[*net.UnixConn]struct{}),
		perUID:       make(map[uint32]int),
		rejectLog:    newRateLimiter(10, time.Second),
		violationLog: newRateLimiter(10, time.Second),
	}, nil
}

func (s *Server) Name() string { return "ipc" }

// Fatal 实现 kernel.FatalReporter：accept 循环连续失败到放弃时，通过本通道上报，
// Kernel 据此反序关闭全部模块并让进程非零退出（见 internal/kernel）
func (s *Server) Fatal() <-chan error { return s.fatal }

// Start 建立监听并起 accept 循环。ctx 仅用于 Start 期间，不被后台循环持有
func (s *Server) Start(context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("ipc: already started")
	}
	s.started = true
	s.mu.Unlock()

	// ① 先拿单例锁。它保证从这行往后，本进程是唯一的 nervud —— 后面对残骸
	// socket 的清理才能无条件安全（没有活实例可能拥有那个 socket）
	if err := s.acquireSingletonLock(); err != nil {
		return err
	}
	// 锁拿到之后，Start 的任何一步失败都必须把它还回去，否则同一 sockPath 再也
	// 起不来（abstract 名字被本进程一直占着）
	ok := false
	defer func() {
		if !ok {
			_ = s.lockLn.Close()
			s.lockLn = nil
		}
	}()

	// ② 父目录由 systemd 的 RuntimeDirectory=nervus 创建（0755，root 所有）。
	// 这里只检查不创建：建目录是特权文件系统操作，该走 authority，而让 ipc
	// 自己 MkdirAll 会在内核里多开一条绕过 Gate 的写路径
	dir := filepath.Dir(s.sockPath)
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("ipc: runtime dir %s unavailable (systemd RuntimeDirectory=): %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("ipc: runtime dir %s is not a directory", dir)
	}

	// ③ 清理残骸。持锁在手，任何遗留的 socket 文件必然是死的
	if err := s.clearStaleSocket(); err != nil {
		return err
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.sockPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("ipc: listen %s: %w", s.sockPath, err)
	}
	// 显式声明：关闭监听时删除 socket 文件，不依赖默认行为
	ln.SetUnlinkOnClose(true)

	// bind 时的权限受 umask 削减（通常落到 0755），必须显式改写。
	// 这个中间窗口是安全的：窗口内权限只会更严，不会更松
	if err := os.Chmod(s.sockPath, socketMode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("ipc: chmod %s: %w", s.sockPath, err)
	}

	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()

	ok = true
	s.log.Info("ipc: listening", "sock", s.sockPath, "mode", socketMode.String(),
		"max_conns", s.limits.MaxConns, "max_conns_per_uid", s.limits.MaxConnsPerUID)
	return nil
}

// singletonLockName 由 sockPath 派生 abstract namespace socket 名字
//
// 用 @ 前缀让 net 包把它当作 abstract socket（Go 约定：首字节替换为 NUL）。
// 由 sockPath 派生而不是写死一个全局名：不同 sockPath 的实例互不干扰（测试
// 友好），同一 sockPath 的实例互斥（生产正确，路径固定为 /run/nervus/nervud.sock）
func (s *Server) singletonLockName() string { return "@" + s.sockPath }

// acquireSingletonLock 用 abstract namespace socket 的 bind 原子性做单例锁
//
// 为什么用它而不是 dial 探测 + unlink 残骸：
//
//	abstract socket 的 bind 由内核保证原子——两个进程同时 bind 同名，只有一个
//	成功，另一个拿 EADDRINUSE。这一步到位地消除了 探测判死->unlink->rebind 之间
//	的 TOCTOU：不可能出现两个实例都判定 旧 socket 已死 然后各自 bind 成功
//
//	而且 abstract socket 不在文件系统，进程退出内核自动回收 —— 没有残骸，
//	不需要 死活探测 那一整套。持锁本身就证明了 没有别的活实例
//
// 权衡（有意接受）：abstract 名字不走文件系统权限，netns 内任何进程都能 bind，
// 因此一个恶意本地进程可以抢先占用本名字来阻止 nervud 启动。对本部署可接受：
// nervud 开机时最先启动（早于任何 app），获取锁时无人竞争；崩溃重启且恰有恶意
// app 抢占的窗口由 systemd StartLimitAction=reboot 兜底自愈。真正 squat-proof
// 的方案是 root-owned 锁文件上的 flock（那需要 depguard 决策，另议）
func (s *Server) acquireSingletonLock() error {
	name := s.singletonLockName()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		// 绝大多数是 EADDRINUSE：另一个 nervud 正持有锁。也可能是被 squat
		return fmt.Errorf("ipc: cannot acquire singleton lock %q (another nervud running?): %w", name, err)
	}
	s.lockLn = ln
	return nil
}

// Stop 停止接客并回收全部连接
//
// 顺序固定：先 close(quit) 让循环知道这是计划内停机，再关监听打断阻塞中的
// Accept，最后强制关闭存活连接打断阻塞中的 Read。反过来做的话，Accept 会先
// 返回一个错误而循环尚不知道该退出，从而走进错误处理与退避分支
func (s *Server) Stop(ctx context.Context) error {
	s.quitOnce.Do(func() { close(s.quit) })

	s.mu.Lock()
	ln := s.ln
	conns := make([]*net.UnixConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	var errs []error
	if ln != nil {
		if err := ln.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close listener: %w", err))
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		// 超时即放弃等待并返回错误。进程仍会退出，安全性由 systemd 重启与
		// MCU 心跳刹停兜底
		errs = append(errs, fmt.Errorf("goroutines not drained: %w", ctx.Err()))
	}

	// 最后释放单例锁。放在连接回收之后：只要还在收尾，就还占着锁，
	// 不给一个抢跑的新实例留出 我以为前一个已经退干净了 的窗口。
	// abstract socket 关闭即由内核回收，无文件残留
	if s.lockLn != nil {
		if err := s.lockLn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close singleton lock: %w", err))
		}
		s.lockLn = nil
	}

	s.log.Info("ipc: stopped")
	return errors.Join(errs...)
}

// clearStaleSocket 清理主 socket 路径上的残骸
//
// 前提：调用方已持有单例锁（acquireSingletonLock）。因此这里【不需要】探测
// 死活——锁已经证明没有别的活实例，那么路径上若有一个 socket，它必然是上次
// 运行留下的残骸（崩溃或 SIGKILL，来不及 unlink），可以无条件删除
//
// 仍然保留的唯一防线：路径存在但【不是 socket】时拒绝而非删除。万一 sockPath
// 被配置错误地指到了一个普通文件，盲删不可逆——这条与单例锁无关，是防手滑
func (s *Server) clearStaleSocket() error {
	fi, err := os.Lstat(s.sockPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ipc: stat %s: %w", s.sockPath, err)
	}

	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("ipc: %s exists and is not a socket (mode %s); refusing to remove", s.sockPath, fi.Mode())
	}

	// 持锁在手，这个 socket 必然是残骸
	s.log.Warn("ipc: removing stale socket", "sock", s.sockPath)
	if err := os.Remove(s.sockPath); err != nil {
		return fmt.Errorf("ipc: remove stale socket %s: %w", s.sockPath, err)
	}
	return nil
}

// acceptBackoffMax 是 accept 连续失败时的退避上限
const acceptBackoffMax = 200 * time.Millisecond

// acceptFailureLimit 是放弃前允许的连续失败次数
//
// 有它是因为退避不能无限重试：监听 fd 若进入永久错误状态，无限循环会把内核
// 变成一个占着 socket 却永远不接客的空壳，而外部看不出区别
const acceptFailureLimit = 32

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	var backoff time.Duration
	failures := 0

	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			// 计划内停机：Stop 已经 close(quit) 并关掉了监听
			select {
			case <-s.quit:
				return
			default:
			}

			failures++
			if failures >= acceptFailureLimit {
				err = fmt.Errorf("ipc: accept failed %d times consecutively: %w", failures, err)
				s.log.Error("ipc: accept loop aborting", "err", err)
				select {
				case s.fatal <- err:
				default:
				}
				return
			}

			// 不自旋：EMFILE/ENFILE 这类错误会立刻重现，全速重试只会把一个核
			// 烧满而不解决任何问题
			if backoff == 0 {
				backoff = time.Millisecond
			} else if backoff < acceptBackoffMax {
				backoff *= 2
			}
			s.log.Warn("ipc: accept failed, backing off",
				"err", err, "backoff", backoff, "consecutive", failures)

			select {
			case <-time.After(backoff):
			case <-s.quit:
				return
			}
			continue
		}

		backoff, failures = 0, 0
		s.admit(c)
	}
}

// admit 对新连接做准入判定
//
// 检查顺序按代价从小到大排列，且全部在分配 goroutine 与读缓冲之前完成。顺序
// 反了的话，攻击者用必然被拒的连接照样能迫使内核先分配 128 KiB 缓冲
func (s *Server) admit(c *net.UnixConn) {
	cred, err := sysprobe.PeerCred(c)
	if err != nil {
		// 读不到内核凭证就无法归因，只能断开。正常连接不会走到这里
		s.reject(c, 0, "peer credentials unavailable", err)
		return
	}

	// App UID 区段检查：一次整数比较，把系统账号、登录用户、root 全部挡在分配
	// 任何资源之前。这条不变量由 authority 拥有，此处复用而不是重新声明
	if err := s.inv.CheckUID(cred.UID); err != nil {
		s.reject(c, cred.UID, "uid outside app range", err)
		return
	}

	// 身份解析：UID 落在区段内不代表它属于某个已注册 Package。手工创建的
	// 系统用户、或者进程还活着但 Package 已被卸载，都会走到这里被拒
	//
	// 排在区段检查【之后】：那是一次整数比较，本步是一次原子 Load 加 map 查找，
	// 先便宜后贵
	caller, err := s.identity.Resolve(cred)
	if err != nil {
		s.reject(c, cred.UID, "uid maps to no registered package", err)
		return
	}

	s.mu.Lock()
	switch {
	case len(s.conns) >= s.limits.MaxConns:
		s.mu.Unlock()
		s.reject(c, cred.UID, "process-wide connection limit reached", nil)
		return
	case s.perUID[cred.UID] >= s.limits.MaxConnsPerUID:
		s.mu.Unlock()
		s.reject(c, cred.UID, "per-uid connection limit reached", nil)
		return
	}
	s.conns[c] = struct{}{}
	s.perUID[cred.UID]++
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.release(c, cred.UID)
		s.serve(c, caller)
	}()
}

// release 把连接从注册表摘掉。必须与 admit 中的登记严格配对，否则 perUID 计数
// 只增不减，该 UID 会被永久锁在额度之外
func (s *Server) release(c *net.UnixConn, uid uint32) {
	_ = c.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.conns[c]; !ok {
		return
	}
	delete(s.conns, c)
	if n := s.perUID[uid]; n <= 1 {
		delete(s.perUID, uid)
	} else {
		s.perUID[uid] = n - 1
	}
}

func (s *Server) reject(c *net.UnixConn, uid uint32, reason string, err error) {
	_ = c.Close()
	if !s.rejectLog.allow() {
		return
	}
	s.auditor.Record(context.Background(), audit.Event{
		Action:  "ipc.ConnectionRejected",
		Subject: fmt.Sprintf("uid:%d", uid),
		Denied:  true,
		Err:     err,
		Detail:  reason,
	})
}

// serve 是单条连接的帧泵：分帧、超时、每帧准入复核，然后把每个良构 Envelope
// 交给连接状态机（conn）。握手（Hello/HelloAck 协商版本、下发 ConnectionLimits）
// 与握手后的 body 分派都在 conn.go
//
// TODO(register): 本模块暂不应被注册进 Kernel。握手已就绪，但请求管线
// （Permission/Policy 裁决、endpoint 解析、Dispatch）尚未落地，Request 目前只回
// UNAVAILABLE。架构 2 要求对外开门前 Identity/Permission/Safety 必须先就绪
func (s *Server) serve(c *net.UnixConn, caller identity.Caller) {
	log := s.log.With("package", caller.PackageID, "uid", caller.UID, "pid", caller.PID)

	// 每连接一块读缓冲并复用，稳态下帧读取不产生堆分配。
	// MaxConns 决定了这部分内存的上界
	buf := make([]byte, MaxFrameBytes)

	// 入站帧速率闸门，单连接一个（§10.11 第一道，见 Limits.MaxFramesPerConnPerSec）
	frameRate := newRateLimiter(s.limits.MaxFramesPerConnPerSec, time.Second)

	// 连接状态机：第一帧必须是 Hello，握手完成前不接受其它 body（conn.go）
	co := newConn(s, c, caller, log)

	for {
		select {
		case <-s.quit:
			return
		default:
		}

		// 读窗口由 conn 当前 phase 决定：握手期用短得多的 HandshakeTimeout，
		// 握手后转入由 Ping/Pong 维持的 IdleTimeout（见 conn.readDeadline）
		if err := c.SetReadDeadline(time.Now().Add(co.readDeadline())); err != nil {
			return
		}
		n, err := ReadFrameHeader(c)
		if err != nil {
			s.logConnExit(log, co.caller, err)
			return
		}

		// 长度已收到，正文必须很快到齐，换用短得多的正文 deadline
		if err := c.SetReadDeadline(time.Now().Add(s.limits.FrameBodyTimeout)); err != nil {
			return
		}
		body, err := ReadFrameBody(c, buf, n)
		if err != nil {
			s.logConnExit(log, co.caller, err)
			return
		}

		// 帧速率闸门：一个死循环刷帧的 App 到这里被截断。正常客户端远够不着
		if !frameRate.allow() {
			log.Warn("ipc: inbound frame rate exceeded, closing connection",
				"limit_per_sec", s.limits.MaxFramesPerConnPerSec)
			s.auditViolation(co.caller, errFrameRateExceeded)
			return
		}

		// 每帧复核身份存活：UID 稳定，用它重新查表即可发现 Package 被卸载
		// 或 Trust 变化（架构 10.5：每次调用做快速存活复核）。发现即断开，
		// 客户端重连时会用新身份重新握手
		//
		// 覆盖范围有限，需说明：这只挡住 卸载/降权 这类 identity 层面的撤权，
		// 且只在客户端【发帧时】触发——一条一言不发的空闲连接要等 IdleTimeout
		// 才被回收。细粒度的 Permission 撤权、以及对空闲连接的主动断开，属于
		// permission 模块与 Envelope 层（EndpointRevoked），不在这里
		if !s.identityStillValid(co.caller) {
			log.Warn("ipc: caller identity revoked mid-connection, closing")
			s.auditViolation(co.caller, errIdentityRevoked)
			return
		}

		// 先解外层小结构并校验良构，之后才谈得上业务分派。架构 10.7 要求这个
		// 顺序：身份、endpoint、方法、长度、权限都过了，才用生成代码去解方法
		// payload，以免未授权输入直接驱动业务解析器
		env, err := parseEnvelope(body)
		if err != nil {
			s.logConnExit(log, co.caller, err)
			return
		}

		// 连接状态机处理：握手协商、下发 ConnectionLimits、握手后按 body 分派。
		// 返回 false 表示应关闭本连接（原因已由 co 审计/记录）
		if !co.handle(env) {
			return
		}
	}
}

// verifyComponent 是架构 10.2「验证声明而不是相信声明」的落点：把客户端在 Hello
// 里自报的 declared_component_id 与内核事实（PID、systemd unit/cgroup、启动记录、
// manifest）核对，返回【核对确认】的 Component ID
//
// 现在是 stub：internal/service 尚未暴露 PID→Component 反查，internal/identity 也
// 还没有 Component 级索引，因此无法核对。stub 返回空字符串（Component 未知）而
// 【不】回退成信任自报值——信任自报等于把身份决策权交给对端，正是 §10.2 禁止的。
// 返回的 error 恒为 nil：既然无法核对，也就无从否证，不能凭空判为不一致
//
// TODO(component-verify): service/identity 就位后改为真正核对，不一致时返回错误，
// 调用方据此回 UNAUTHENTICATED Failure HelloAck
func (s *Server) verifyComponent(_ identity.Caller, _ string) (string, error) {
	return "", nil
}

// connectionLimits 把服务端强制的预算投影成下发给 SDK 的 ConnectionLimits
// （架构 10.11 的 wire 投影）。SDK 据此自律；服务端不因告知过就放松执法
//
// 只填【当前真正强制】的项与 schema 冻结的固定常量：
//   - max_frame_bytes         frame.go 已强制（§10.3 硬上限 128 KiB）
//   - idle_timeout_ms         serve 的空闲 deadline 已强制
//   - default_method_payload  §10.3 冻结的 16 KiB 默认额度
//
// in-flight / outbound / subscription / method-timeout 预算随 Envelope 执行层落地
// 再填——现在下发一个没人强制的数字，只会让 SDK 以为它已经生效（与 Limits 结构体
// 刻意不预定义未强制字段同理）
func (s *Server) connectionLimits() *ipcv1.ConnectionLimits {
	return &ipcv1.ConnectionLimits{
		MaxFrameBytes:             MaxFrameBytes,
		DefaultMethodPayloadBytes: defaultMethodPayloadBytes,
		IdleTimeoutMs:             uint32(s.limits.IdleTimeout / time.Millisecond),
	}
}

// identityStillValid 用连接建立时的凭证重新解析身份，判断它是否仍然有效且未变
//
// 复用 caller 里已经拿到的内核凭证字段（UID/GID/PID 都来自 SO_PEERCRED，
// 连接存续期间不变），不重新读 socket
func (s *Server) identityStillValid(caller identity.Caller) bool {
	fresh, err := s.identity.Resolve(sysprobe.Ucred{UID: caller.UID, GID: caller.GID, PID: caller.PID})
	if err != nil {
		return false // Package 已被卸载
	}
	// Package ID 或 Trust 变化，都视为身份已变，旧连接不再可信
	return fresh.PackageID == caller.PackageID && fresh.Trust == caller.Trust
}

// 违规审计用的哨兵错误，让审计记录能被离线规则精确归类
var (
	errFrameRateExceeded = errors.New("inbound frame rate exceeded")
	errIdentityRevoked   = errors.New("caller identity revoked mid-connection")
)

// logConnExit 区分正常断开与协议违规。两者的处理和审计完全不同，混在一起会让
// 真正的攻击迹象淹没在客户端正常退出的噪音里
func (s *Server) logConnExit(log *slog.Logger, caller identity.Caller, err error) {
	switch {
	case errors.Is(err, io.EOF):
		log.Debug("ipc: peer closed connection")
	case isProtocolViolation(err):
		log.Warn("ipc: protocol violation, closing connection", "err", err)
		s.auditViolation(caller, err)
	case errors.Is(err, os.ErrDeadlineExceeded):
		log.Debug("ipc: read deadline exceeded, closing connection")
	default:
		log.Debug("ipc: connection closed", "err", err)
	}
}

// auditViolation 记一条违规审计，限速，并【填上 Subject】以便归因到 Package/UID
//
// 之前这条路径既不限速（畸形帧可被恶意连接刷成审计放大器），也不填 Subject
// （无法归因到是谁干的）——两个都在这里补上
func (s *Server) auditViolation(caller identity.Caller, err error) {
	if !s.violationLog.allow() {
		return
	}
	s.auditor.Record(context.Background(), audit.Event{
		Action:  "ipc.ProtocolViolation",
		Subject: caller.String(),
		Denied:  true,
		Err:     err,
	})
}

// auditUnsupported 记一条「收到本 build 尚未实现的 body」审计，限速并填 Subject
//
// 与 auditViolation 分开 Action 是为了让离线规则能把「能力缺口」（未实现）与
// 「协议违规 / 潜在攻击」区分开——混进同一个 Action，真正的攻击迹象会被未实现
// 路径的噪音淹没。共用 violationLog 令牌桶：两者都以「关闭连接」收场，一条连接
// 至多产出一条，限速要挡的是「大量连接各刷一条」，共用即可
func (s *Server) auditUnsupported(caller identity.Caller, err error) {
	if !s.violationLog.allow() {
		return
	}
	s.auditor.Record(context.Background(), audit.Event{
		Action:  "ipc.UnsupportedBody",
		Subject: caller.String(),
		Denied:  true,
		Err:     err,
	})
}

// rateLimiter 是给审计路径用的最小令牌桶
//
// 不用 x/time/rate：那会为一件二十行能解决的事引入一个 TCB 依赖
type rateLimiter struct {
	mu       sync.Mutex
	burst    int
	tokens   int
	interval time.Duration
	last     time.Time
}

func newRateLimiter(burst int, interval time.Duration) rateLimiter {
	return rateLimiter{burst: burst, tokens: burst, interval: interval, last: time.Now()}
}

func (r *rateLimiter) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if now.Sub(r.last) >= r.interval {
		r.tokens = r.burst
		r.last = now
	}
	if r.tokens <= 0 {
		return false
	}
	r.tokens--
	return true
}
