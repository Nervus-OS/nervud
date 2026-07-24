// SO_PEERCRED 身份准入、每连接一次读 Request -> 处理 -> 写 Response -> 关。
// 具体命令处理在 handlers.go。
package admin

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

	"github.com/nervus-os/nervud/internal/adminwire"
	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/pkgregistry"
	"github.com/nervus-os/nervud/internal/sysprobe"
)

// DefaultStagingDir 是 nervud 掌控的动态安装 staging 根。与 PackageRoot
// （/var/lib/nervus/packages）同处 /var/lib/nervus 之下 = 同一文件系统，安装期
// 把 staging 目录 renameat2 进 PackageRoot 才不会跨文件系统失败（EXDEV）。
// preflight 负责在启动时把它建好（0700、属主 nervud）。
const DefaultStagingDir = "/var/lib/nervus/staging"

// socketMode 是管理 socket 的文件权限：0600，只有 socket 属主（运行 nervud 的
// 账户，生产为 root）能连。这是第一道 FS 层过滤；真正的准入是 accept 后的
// SO_PEERCRED 校验（见 handleConn）。
const socketMode fs.FileMode = 0o600

// PackageService 是本包对 pkgregistry.Module 的窄接口依赖：装包/卸载/停用启用。
// 消费者定义接口，*pkgregistry.Module 隐式满足。所有安全复核都在 Module 内部，
// 本包只转调。
type PackageService interface {
	Install(ctx context.Context, tx pkgregistry.InstallTransaction) (pkgregistry.Entry, error)
	Uninstall(ctx context.Context, pkgID string) error
	SetComponentEnabled(ctx context.Context, pkgID, compID string, enabled bool) error
}

// PackageLister 是对 pkgregistry.Registry 的窄接口依赖：列出全部已装 Package
// （list 命令）。*pkgregistry.Registry 隐式满足。
type PackageLister interface {
	List() []pkgregistry.Entry
}

// PermissionSetter 是对 permission.Registry 的窄接口依赖：设置运行期授予状态
// （grant/revoke）。*permission.Registry 隐式满足。
type PermissionSetter interface {
	SetRuntimeState(packageID, permission string, state permission.GrantState) error
}

// Config 是管理服务的装配输入。
type Config struct {
	// SockPath 是管理通道 UDS 路径，生产固定 adminwire.DefaultSockPath。
	SockPath string
	// StagingRoot 是 nervud 掌控的 staging 根，默认 DefaultStagingDir。
	StagingRoot string
	// AdminUID 是被许可发管理命令的对端 UID。装配时显式传入（main.go 传
	// os.Geteuid = 运行 nervud 的账户，生产为 0/root）；不设默认，因为 0 本身
	// 是合法值，无法用零值区分未设置。
	AdminUID uint32

	Packages    PackageService
	Registry    PackageLister
	Permissions PermissionSetter
	Auditor     audit.Recorder
	Log         *slog.Logger
}

// Server 拥有管理通道 UDS。生命周期契约同 ipc.Server：Start 快速返回，后台 accept
// 循环只听 Stop 关闭的 quit，不听 Start(ctx) 的 ctx。
type Server struct {
	sockPath    string
	stagingRoot string
	adminUID    uint32

	pkgs  PackageService
	reg   PackageLister
	perms PermissionSetter
	aud   audit.Recorder
	log   *slog.Logger

	ln *net.UnixListener

	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup
	fatal    chan error
}

// New 校验必填依赖并构造 Server。缺任何一个安全相关依赖都在装配期失败 - 管理
// 通道没有一半可用的安全降级。
func New(cfg Config) (*Server, error) {
	if cfg.SockPath == "" {
		cfg.SockPath = adminwire.DefaultSockPath
	}
	if !filepath.IsAbs(cfg.SockPath) {
		return nil, fmt.Errorf("admin: SockPath %q must be absolute", cfg.SockPath)
	}
	if cfg.StagingRoot == "" {
		cfg.StagingRoot = DefaultStagingDir
	}
	if !filepath.IsAbs(cfg.StagingRoot) {
		return nil, fmt.Errorf("admin: StagingRoot %q must be absolute", cfg.StagingRoot)
	}
	if cfg.Packages == nil {
		return nil, errors.New("admin: Packages is required")
	}
	if cfg.Registry == nil {
		return nil, errors.New("admin: Registry is required")
	}
	if cfg.Permissions == nil {
		return nil, errors.New("admin: Permissions is required")
	}
	if cfg.Auditor == nil {
		return nil, errors.New("admin: Auditor is required")
	}
	if cfg.Log == nil {
		return nil, errors.New("admin: Log is required")
	}
	return &Server{
		sockPath:    cfg.SockPath,
		stagingRoot: filepath.Clean(cfg.StagingRoot),
		adminUID:    cfg.AdminUID,
		pkgs:        cfg.Packages,
		reg:         cfg.Registry,
		perms:       cfg.Permissions,
		aud:         cfg.Auditor,
		log:         cfg.Log,
		quit:        make(chan struct{}),
		fatal:       make(chan error, 1),
	}, nil
}

func (s *Server) Name() string { return "admin" }

// Fatal 实现 kernel.FatalReporter：accept 循环不可恢复地失败时上报，内核据此
// 反序关闭并非零退出。
func (s *Server) Fatal() <-chan error { return s.fatal }

// Start 建立监听并起 accept 循环。ctx 仅用于 Start 期间。
func (s *Server) Start(context.Context) error {
	// staging 根正常由 preflight 建好（0700、属主 nervud）。这里再 MkdirAll 一次
	// 兜底：开发机用 -dev-skip-preflight 起 nervud 时 preflight 不跑，装包仍要能用。
	// MkdirAll 对已存在目录是 no-op（不改属主/权限），因此不与 preflight 的 squat
	// 校验冲突 - 生产路径上 preflight 先跑并已校验过属主。
	if err := os.MkdirAll(s.stagingRoot, 0o700); err != nil {
		return fmt.Errorf("admin: ensure staging root %s: %w", s.stagingRoot, err)
	}

	// 父目录（/run/nervus）由 systemd RuntimeDirectory + preflight 保证存在，
	// 这里只清残骸、不建目录（建目录是特权 FS 操作，不在本模块职责内）。
	if err := s.clearStaleSocket(); err != nil {
		return err
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.sockPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("admin: listen %s: %w", s.sockPath, err)
	}
	ln.SetUnlinkOnClose(true)

	// bind 时权限受 umask 削减，显式收紧到 0600。中间窗口只会更严不会更松。
	if err := os.Chmod(s.sockPath, socketMode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("admin: chmod %s: %w", s.sockPath, err)
	}

	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()

	s.log.Info("admin: listening", "sock", s.sockPath, "mode", socketMode.String(), "admin_uid", s.adminUID)
	return nil
}

// Stop 关闭监听并等待 accept 循环与在途连接退出。
func (s *Server) Stop(ctx context.Context) error {
	s.quitOnce.Do(func() { close(s.quit) })

	var errs []error
	if s.ln != nil {
		if err := s.ln.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close listener: %w", err))
		}
	}

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		errs = append(errs, fmt.Errorf("admin goroutines not drained: %w", ctx.Err()))
	}

	s.log.Info("admin: stopped")
	return errors.Join(errs...)
}

// clearStaleSocket 删除上次运行遗留的 socket 文件。管理通道没有 ipc 那套单例锁
// （它不是并发热点），因此这里保留一道防线：路径存在但不是 socket 时拒绝而非
// 盲删 - 防 SockPath 被配置错误地指到普通文件。
func (s *Server) clearStaleSocket() error {
	fi, err := os.Lstat(s.sockPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("admin: stat %s: %w", s.sockPath, err)
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("admin: %s exists and is not a socket (mode %s); refusing to remove", s.sockPath, fi.Mode())
	}
	if err := os.Remove(s.sockPath); err != nil {
		return fmt.Errorf("admin: remove stale socket %s: %w", s.sockPath, err)
	}
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			select {
			case <-s.quit:
				return // 计划内停机
			default:
			}
			// 监听 fd 出错：管理通道不做退避重试自愈（它不是关键路径），直接上报
			// fatal，让 systemd 重启整个 nervud - 比在坏 fd 上空转更干净。
			err = fmt.Errorf("admin: accept: %w", err)
			s.log.Error("admin: accept loop aborting", "err", err)
			select {
			case s.fatal <- err:
			default:
			}
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(c)
		}()
	}
}

// connTimeout 是单条管理连接从建立到完成一次读 Request -> 处理 -> 写 Response
// 的整体上限。管理操作都很快（装包的 renameat2/落盘是秒级），60s 远超任何正常
// 耗时；它的作用是防连上不说话或不读响应的对端把 handleConn goroutine 挂
// 死，从而在 Stop 时拖住整条停机等待。
const connTimeout = 60 * time.Second

// handleConn 处理单条连接：SO_PEERCRED 准入 -> 读一个 Request -> 处理 -> 写 Response
// -> 关。一条连接只服务一条命令，无长连接状态机。
func (s *Server) handleConn(c *net.UnixConn) {
	defer func() { _ = c.Close() }()

	// 整条交换设一个有限 deadline：慢/沉默的对端不得挂死本 goroutine（否则拖住 Stop）。
	if err := c.SetDeadline(time.Now().Add(connTimeout)); err != nil {
		return
	}

	cred, err := sysprobe.PeerCred(c)
	if err != nil {
		// 读不到内核凭证 = 无法归因，断开。正常连接不会走到这里。
		s.audit("admin.Rejected", "", true, err, "peer credentials unavailable")
		return
	}
	if cred.UID != s.adminUID {
		// 只有运维身份（运行 nervud 的账户 / root）可发管理命令。0600 已挡住大多数，
		// SO_PEERCRED 是纵深防御：内核给的 UID，对端无法伪造。
		s.audit("admin.Rejected", fmt.Sprintf("uid:%d", cred.UID), true, nil, "uid not permitted")
		_ = adminwire.WriteTo(c, adminwire.Response{
			OK: false, Code: adminwire.CodeUnauthorized,
			Message: "not authorized to use the admin channel",
		})
		return
	}

	var req adminwire.Request
	if err := adminwire.ReadFrom(c, &req); err != nil {
		if !errors.Is(err, io.EOF) {
			s.log.Debug("admin: read request failed", "err", err)
		}
		return
	}

	resp := s.dispatch(context.Background(), req)
	if err := adminwire.WriteTo(c, resp); err != nil {
		s.log.Debug("admin: write response failed", "err", err)
	}
}

// audit 记一条管理面审计。Subject 归因到对端/包，Denied 标注拒绝。
func (s *Server) audit(action, subject string, denied bool, err error, detail string) {
	s.aud.Record(context.Background(), audit.Event{
		Action: action, Subject: subject, Denied: denied, Err: err, Detail: detail,
	})
}
