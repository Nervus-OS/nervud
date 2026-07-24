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

// socketMode 是没有放行系统服务时的 socket 权限：0600，只有属主（运行 nervud
// 的账户，生产为 root）能连。这是第一道 FS 层过滤；真正的准入是 accept 后的
// SO_PEERCRED 校验（见 handleConn）。
const socketMode fs.FileMode = 0o600

// socketModeWithService 是放行了系统服务（pkgmanagerd）时的 socket 权限：0660，
// 配合把 socket 的【组】chown 成该服务的 GID。
//
// 为什么必须动 FS 层：0600 之下 pkgmanagerd（UID 20000+）连 connect() 都过不了，
// SO_PEERCRED 校验根本没机会执行——只在 handleConn 里放行 UID 是无效的。
//
// 为什么不用 0666 让 SO_PEERCRED 独自把关：那样任何本地进程都能连上再被拒，
// FS 这一层就退化成摆设，还白送一个消耗连接槽的口子。0660 + 组精确地只放
// 「root 与那一个服务」两者。
//
// 本系统里 Package 的 GID 恒等于其 UID（见 service.buildStartReq 的
// GID: e.UID），所以组直接取 ServiceUID 即可，不需要额外的组管理。
const socketModeWithService fs.FileMode = 0o660

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
	// AdminUID 是被许可发管理命令的运维身份 UID。装配时显式传入（main.go 传
	// os.Geteuid = 运行 nervud 的账户，生产为 0/root）；不设默认，因为 0 本身
	// 是合法值，无法用零值区分未设置。
	AdminUID uint32

	// ServiceUID 是唯一被额外放行的系统服务 UID（nervus.pkgmanagerd）。
	// 0 表示不放行任何服务，本通道退回只认运维身份。
	//
	// 为什么需要它：装包必须由一个【系统服务】对 App 提供（App 不可能是 root），
	// 而系统服务跑在 App UID 段（20000-59999），按单值 root 判定连不上本通道。
	//
	// 为什么不让 pkgmanagerd 直接以 root 跑：那会让它脱离包体系——拿不到稳定
	// UID、不受 identity 的 UID↔Package 一一对应约束、也不在 pkgregistry 保护
	// 名单的语义之内。而那份名单里明写着 "nervus.pkgmanagerd/main"，设计意图
	// 就是它是一个包。
	//
	// 为什么是单个而不是一组：这条通道能做的事（装包、卸载、授撤权限）是全系统
	// 最敏感的一批，放行面越窄越好。真出现第二个需要它的服务时，应当先问
	// 「它凭什么」，而不是往列表里再加一行。
	//
	// 【安全边界没有放宽】：放行的是「谁能连上这条 socket」，不是「连上能做什么」。
	// 全部命令仍旧只是把请求投递给同进程的 pkgregistry.Module，签名、digest、
	// 升级裁决、权限交集一律在那里复核。pkgmanagerd 不做任何安全判定。
	//
	// 装配时由 main.go 从 Registry 查 nervus.pkgmanagerd 的 UID 填入；查不到
	// （未安装）就留 0——不报错，也不放宽。
	ServiceUID uint32

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
	serviceUID  uint32
	// allowedUIDs 是 adminUID + serviceUID 的合并集合，构造时冻结、运行期只读。
	// 用 map 而不是两次比较：判定在每条连接上执行，集合语义更直白，
	// 将来真要放宽也不必改判定逻辑。
	allowedUIDs map[uint32]struct{}

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
	// 合并允许集合。运维身份恒在其中；ServiceUID 为 0 时不加入——UID 0 只能
	// 通过 AdminUID 这条明确的路径进来，绝不接受从「服务放行」这个口子悄悄
	// 混进一个 root。这不是理论风险：ServiceUID 由 Registry 查询结果填充，
	// 查询失败或包未安装时的零值恰好就是 0。
	allowed := map[uint32]struct{}{cfg.AdminUID: {}}
	if cfg.ServiceUID != 0 {
		allowed[cfg.ServiceUID] = struct{}{}
	}

	return &Server{
		sockPath:    cfg.SockPath,
		stagingRoot: filepath.Clean(cfg.StagingRoot),
		adminUID:    cfg.AdminUID,
		serviceUID:  cfg.ServiceUID,
		allowedUIDs: allowed,
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

	// 顺序要紧：先 chown 组、再放宽 mode。
	//
	// 反过来做（先 0660 再 chown）会留下一个窗口：那一瞬间 socket 的组还是
	// nervud 的主组（生产为 root 组），0660 等于把连接权发给了 root 组的全部
	// 成员。窗口再短也是真实可利用的，而调换顺序的成本为零。
	mode := socketMode
	if s.serviceUID != 0 {
		// 本系统 Package 的 GID 恒等于 UID，故组直接取 serviceUID。
		// -1 表示不改属主，只改组。
		if err := os.Chown(s.sockPath, -1, int(s.serviceUID)); err != nil {
			_ = ln.Close()
			return fmt.Errorf("admin: chown group %s to %d: %w", s.sockPath, s.serviceUID, err)
		}
		mode = socketModeWithService
	}

	// bind 时权限受 umask 削减，这里显式设定。没有服务放行时是 0600。
	if err := os.Chmod(s.sockPath, mode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("admin: chmod %s: %w", s.sockPath, err)
	}

	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()

	s.log.Info("admin: listening",
		"sock", s.sockPath, "mode", mode.String(),
		"admin_uid", s.adminUID, "service_uid", s.serviceUID)
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
	if _, ok := s.allowedUIDs[cred.UID]; !ok {
		// 只有运维身份（运行 nervud 的账户 / root）与显式放行的系统服务
		// （pkgmanagerd）可发管理命令。SO_PEERCRED 是纵深防御：内核给的 UID，
		// 对端无法伪造。
		//
		// socket 权限【仍是 0600】，没有改成 0660 + 组：那样等于把准入交给
		// 文件系统的组成员关系，而组是运维可改的；这里要的是「只有这几个
		// 特定 UID」，判定权必须留在内核凭证上。0600 之下 pkgmanagerd 连不上
		// 是预期的——见下方 socket 属主设置。
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
