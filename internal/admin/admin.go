// SO_PEERCRED 身份准入, 每连接一次读 Request -> 处理 -> 写 Response -> 关.
// 具体命令处理在 handlers.go.
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

// DefaultStagingDir 是 nervud 掌控的动态安装 staging 根. 与 PackageRoot
//
//	(/var/lib/nervus/packages) 同处 /var/lib/nervus 之下 = 同一文件系统, 安装期
//
// 把 staging 目录 renameat2 进 PackageRoot 才不会跨文件系统失败 (EXDEV).
// preflight 负责在启动时把它建好 (0700, 属主 nervud).
const DefaultStagingDir = "/var/lib/nervus/staging"

// PermissionPackageAdmin 是连接本通道所需的权限. 它定义在内核 catalog bootstrap
// 里 (SYSTEM_ONLY + PLATFORM 信任 + platform-release 签名角色).
//
// 内核不认识任何具体的 Package ID: 以前这里是 main.go 的一个
// "nervus.pkgmanagerd" 常量, 现在换成一条包必须显式声明, 且经过裁决的权限.
const PermissionPackageAdmin = "perm.pkg.admin"

// socketMode 是没有放行任何包时的 socket 权限: 0600, 只有属主 (运行 nervud
// 的账户, 生产为 root) 能连. 这是第一道 FS 层过滤; 真正的准入是 accept 后的
// SO_PEERCRED 校验 (见 handleConn).
const socketMode fs.FileMode = 0o600

// socketModeWithService 是放行了一个包时的 socket 权限: 0660, 配合把 socket 的
// 组chown 成该包的 GID.
//
// 为什么必须动 FS 层: 0600 之下装包服务 (UID 20000+) 连 connect() 都过不了,
// SO_PEERCRED 校验根本没机会执行 - 只在 handleConn 里放行 UID 是无效的.
//
// 为什么不用 0666 让 SO_PEERCRED 独自把关: 那样任何本地进程都能连上再被拒,
// FS 这一层就退化成摆设, 还白送一个消耗连接槽的口子. 0660 + 组精确地只放
// "root 与那一个包"两者.
//
// 本系统里 Package 的 GID 恒等于其 UID (见 service.buildStartReq 的
// GID: e.UID), 所以组直接取该包的 UID, 不需要额外的组管理.
const socketModeWithService fs.FileMode = 0o660

// PackageService 是本包对 pkgregistry.Module 的窄接口依赖: 装包/卸载/停用启用.
// 消费者定义接口, *pkgregistry.Module 隐式满足. 所有安全复核都在 Module 内部,
// 本包只转调.
type PackageService interface {
	Install(ctx context.Context, tx pkgregistry.InstallTransaction) (pkgregistry.Entry, error)
	Uninstall(ctx context.Context, pkgID string) error
	SetComponentEnabled(ctx context.Context, pkgID, compID string, enabled bool) error
}

// PackageLister 是对 pkgregistry.Registry 的窄接口依赖: 列出全部已装 Package
//
//	(list 命令). *pkgregistry.Registry 隐式满足.
type PackageLister interface {
	List() []pkgregistry.Entry
}

// PermissionSetter 是对 permission.Registry 的窄接口依赖: 设置运行期授予状态
//
//	(grant/revoke), 以及查询某个包是否持有某项权限 (准入判定用).
//
// *permission.Registry 隐式满足.
type PermissionSetter interface {
	SetRuntimeState(packageID, permission string, state permission.GrantState) error
	Allowed(packageID, permission string) bool
}

// Config 是管理服务的装配输入.
type Config struct {
	// SockPath 是管理通道 UDS 路径, 生产固定 adminwire.DefaultSockPath.
	SockPath string
	// StagingRoot 是 nervud 掌控的 staging 根, 默认 DefaultStagingDir.
	StagingRoot string
	// AdminUID 是被许可发管理命令的运维身份 UID. 装配时显式传入 (main.go 传
	// os.Geteuid = 运行 nervud 的账户, 生产为 0/root); 不设默认, 因为 0 本身
	// 是合法值, 无法用零值区分未设置.
	AdminUID uint32

	Packages    PackageService
	Registry    PackageLister
	Permissions PermissionSetter
	Auditor     audit.Recorder
	Log         *slog.Logger
}

// Server 拥有管理通道 UDS. 生命周期契约同 ipc.Server: Start 快速返回, 后台 accept
// 循环只听 Stop 关闭的 quit, 不听 Start(ctx) 的 ctx.
type Server struct {
	sockPath    string
	stagingRoot string
	adminUID    uint32
	// allowedUIDs 是运维 UID 加上全部持有 PermissionPackageAdmin 的包 UID.
	// 在 Start 里一次算好, 之后只读.
	//
	// 用 map 而不是逐个比较: 判定在每条连接上执行, 集合语义更直白.
	allowedUIDs map[uint32]struct{}

	// admittedUID 是被放行的那个包的 UID, Start 里解析. socket 的组与 staging
	// 目录的属主都取它 - 两者必须是同一个值, 否则会出现"连得上但写不进
	// staging"这类分裂状态.
	//
	// 0 表示没有包被放行 (最小镜像, 开发机, 或出现多个持有者时的 fail closed).
	// 那时只有 root 用这条通道, 不需要转交属主.
	admittedUID uint32

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

// New 校验必填依赖并构造 Server. 缺任何一个安全相关依赖都在装配期失败 - 管理
// 通道没有一半可用的安全降级.
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
	// 允许集合此刻只含运维身份. 持有 perm.pkg.admin 的包在 Start 里补入 -
	// 装配期启动扫描还没跑, UID 与权限裁决结果都还不存在
	//  (见 admitPermittedPackages).
	allowed := map[uint32]struct{}{cfg.AdminUID: {}}

	return &Server{
		sockPath:    cfg.SockPath,
		stagingRoot: filepath.Clean(cfg.StagingRoot),
		adminUID:    cfg.AdminUID,
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

// Fatal 实现 kernel.FatalReporter: accept 循环不可恢复地失败时上报, 内核据此
// 反序关闭并非零退出.
func (s *Server) Fatal() <-chan error { return s.fatal }

// Start 建立监听并起 accept 循环. ctx 仅用于 Start 期间.
func (s *Server) Start(context.Context) error {
	// staging 根正常由 preflight 建好 (0700, 属主 nervud). 这里再 MkdirAll 一次
	// 兜底: 开发机用 -dev-skip-preflight 起 nervud 时 preflight 不跑, 装包仍要能用.
	// MkdirAll 对已存在目录是 no-op (不改属主/权限), 因此不与 preflight 的 squat
	// 校验冲突 - 生产路径上 preflight 先跑并已校验过属主.
	if err := os.MkdirAll(s.stagingRoot, 0o711); err != nil {
		return fmt.Errorf("admin: ensure staging root %s: %w", s.stagingRoot, err)
	}
	// 0711 而不是 0700: 系统服务要能穿过这个根进到自己那个 stage-* 目录里,
	// 但不该能列出里面有什么 - 别的包的 staging 与它无关.
	//
	// 显式 Chmod 而不是只靠上面的 MkdirAll: MkdirAll 对已存在目录是 no-op,
	// 而 preflight (或旧版本的本函数) 建的是 0700. 不改的话装包在一台升级上来
	// 的机器上仍然失败, 而失败信息是 permission denied, 看不出是根的权限位.
	if err := os.Chmod(s.stagingRoot, 0o711); err != nil {
		return fmt.Errorf("admin: chmod staging root %s: %w", s.stagingRoot, err)
	}

	// 父目录 (/run/nervus) 由 systemd RuntimeDirectory + preflight 保证存在,
	// 这里只清残骸, 不建目录 (建目录是特权 FS 操作, 不在本模块职责内).
	if err := s.clearStaleSocket(); err != nil {
		return err
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.sockPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("admin: listen %s: %w", s.sockPath, err)
	}
	ln.SetUnlinkOnClose(true)

	// 按权限放行. 必须在这里而不是装配期: 本模块注册在 pkgregistry 之后,
	// 因此本函数跑在启动扫描之后, 那时 UID 已分配, 权限已裁决.
	admitted := s.admitPermittedPackages()

	// 顺序要紧: 先 chown 组, 再放宽 mode.
	//
	// 反过来做 (先 0660 再 chown) 会留下一个窗口: 那一瞬间 socket 的组还是
	// nervud 的主组 (生产为 root 组), 0660 等于把连接权发给了 root 组的全部
	// 成员. 窗口再短也是真实可利用的, 而调换顺序的成本为零.
	mode := socketMode
	switch len(admitted) {
	case 0:
		// 只有运维身份, 保持 0600
	case 1:
		s.admittedUID = admitted[0]
		// 本系统 Package 的 GID 恒等于 UID. -1 表示不改属主, 只改组
		if err := os.Chown(s.sockPath, -1, int(s.admittedUID)); err != nil {
			_ = ln.Close()
			return fmt.Errorf("admin: chown group %s to %d: %w", s.sockPath, s.admittedUID, err)
		}
		mode = socketModeWithService
	default:
		// 一个 Unix socket 只有一个组, 表达不了"放行多个包".
		//
		// 这里 fail closed 保持 0600 而不是随便挑一个: 挑一个会让另外那些包
		// 在 allowedUIDs 里看着被放行, 实际却连 connect() 都过不去, 症状是
		// "权限配对了但连不上" - 那是最难查的一类.
		//
		// 正常情况下不会走到这里: perm.pkg.admin 是 SYSTEM_ONLY + PLATFORM +
		// platform-release, 出现第二个持有者说明平台构建配错了.
		// 只影响装包, 运维通道仍可用, 因此不拖垮内核启动.
		s.log.Error("admin: multiple packages hold "+PermissionPackageAdmin+
			"; a Unix socket has only one group, refusing all of them",
			"uids", admitted, "permission", PermissionPackageAdmin)
		s.allowedUIDs = map[uint32]struct{}{s.adminUID: {}}
	}

	// bind 时权限受 umask 削减, 这里显式设定. 没有包被放行时是 0600.
	if err := os.Chmod(s.sockPath, mode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("admin: chmod %s: %w", s.sockPath, err)
	}

	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()

	s.log.Info("admin: listening",
		"sock", s.sockPath, "mode", mode.String(),
		"admin_uid", s.adminUID, "admitted_uid", s.admittedUID)
	return nil
}

// Stop 关闭监听并等待 accept 循环与在途连接退出.
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

// clearStaleSocket 删除上次运行遗留的 socket 文件. 管理通道没有 ipc 那套单例锁
//
//	(它不是并发热点), 因此这里保留一道防线: 路径存在但不是 socket 时拒绝而非
//
// 盲删 - 防 SockPath 被配置错误地指到普通文件.
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
			// 监听 fd 出错: 管理通道不做退避重试自愈 (它不是关键路径), 直接上报
			// fatal, 让 systemd 重启整个 nervud - 比在坏 fd 上空转更干净.
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
// 的整体上限. 管理操作都很快 (装包的 renameat2/落盘是秒级), 60s 远超任何正常
// 耗时; 它的作用是防连上不说话或不读响应的对端把 handleConn goroutine 挂
// 死, 从而在 Stop 时拖住整条停机等待.
const connTimeout = 60 * time.Second

// handleConn 处理单条连接: SO_PEERCRED 准入 -> 读一个 Request -> 处理 -> 写 Response
// -> 关. 一条连接只服务一条命令, 无长连接状态机.
func (s *Server) handleConn(c *net.UnixConn) {
	defer func() { _ = c.Close() }()

	// 整条交换设一个有限 deadline: 慢/沉默的对端不得挂死本 goroutine (否则拖住 Stop).
	if err := c.SetDeadline(time.Now().Add(connTimeout)); err != nil {
		return
	}

	cred, err := sysprobe.PeerCred(c)
	if err != nil {
		// 读不到内核凭证 = 无法归因, 断开. 正常连接不会走到这里.
		s.audit("admin.Rejected", "", true, err, "peer credentials unavailable")
		return
	}
	if _, ok := s.allowedUIDs[cred.UID]; !ok {
		// 只有运维身份 (运行 nervud 的账户 / root) 与显式放行的系统服务
		//  (pkgmanagerd) 可发管理命令. SO_PEERCRED 是纵深防御: 内核给的 UID,
		// 对端无法伪造.
		//
		// socket 权限仍是 0600, 没有改成 0660 + 组: 那样等于把准入交给
		// 文件系统的组成员关系, 而组是运维可改的; 这里要的是"只有这几个
		// 特定 UID", 判定权必须留在内核凭证上. 0600 之下 pkgmanagerd 连不上
		// 是预期的 - 见下方 socket 属主设置.
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

// audit 记一条管理面审计. Subject 归因到对端/包, Denied 标注拒绝.
func (s *Server) audit(action, subject string, denied bool, err error, detail string) {
	s.aud.Record(context.Background(), audit.Event{
		Action: action, Subject: subject, Denied: denied, Err: err, Detail: detail,
	})
}

// resolveServiceUID 从 Registry 里查出被放行服务的 UID 并补进允许集合.
//
// 只在 Start 里调用一次. 运行期不重查: pkgmanagerd 是系统镜像包, 它的 UID
// 一旦分配就跨重启不变, 而且系统包不能被动态卸载 (ErrSystemPackageImmutable).
//
// UID 0 一律丢弃 - root 只能通过 AdminUID 这条明确路径进来, 绝不接受从
// "服务放行"这个口子悄悄混进一个 root. 这不是理论风险: 查不到时的零值
// 恰好就是 0.
// admitPermittedPackages 把每一个持有 PermissionPackageAdmin 的包的 UID 加进
// 放行集合.
//
// 判据是权限, 不是 Package ID. 以前这里比对的是装配期硬编码的
// "nervus.pkgmanagerd"; 现在内核不认识任何具体的包名, 只认"谁在 manifest 里
// 声明了 perm.pkg.admin 并通过了裁决".
//
// 放行面并没有因此变宽: perm.pkg.admin 是 SYSTEM_ONLY + PLATFORM 信任 +
// platform-release 签名角色, IntersectAt 会把动态安装包, OEM 包和开发构建里
// 降级到 Ordinary 的包全部挡在外面. 区别只是这条约束现在写在权限目录里,
// 可以被审计, 被测试, 而不是散落在 main.go 的一个常量上.
//
// 必须在 Start 里调用而不是装配期: 本模块注册在 pkgregistry 之后, 因此
// 本函数跑在启动扫描之后, 那时 UID 已分配, 权限已裁决. 装配期两者都还不存在.
func (s *Server) admitPermittedPackages() []uint32 {
	var admitted []uint32
	for _, e := range s.reg.List() {
		pkgID := e.Manifest.PackageID
		if !s.perms.Allowed(pkgID, PermissionPackageAdmin) {
			continue
		}
		// UID 0 说明启动扫描没给这个包分配到 UID. 放行 0 等于放行 root,
		// 而 root 的准入由 adminUID 单独表达 - 这里必须拒绝, 否则一个
		// 分配失败的包会静默获得运维身份
		if e.UID == 0 {
			s.log.Warn("admin: package holds "+PermissionPackageAdmin+" but has uid 0; refusing to admit",
				"package_id", pkgID)
			continue
		}
		s.allowedUIDs[e.UID] = struct{}{}
		admitted = append(admitted, e.UID)
		s.log.Info("admin: package admitted by permission",
			"package_id", pkgID, "uid", e.UID, "permission", PermissionPackageAdmin)
	}
	if len(admitted) == 0 {
		// 最小镜像或开发机上没有装包服务是正常的: 本通道退回只认运维身份.
		// 不报错也不放宽 - 这条链路缺失只意味着"装不了包", 不该拖垮内核启动
		s.log.Info("admin: no package holds " + PermissionPackageAdmin + "; channel is operator-only")
	}
	return admitted
}
