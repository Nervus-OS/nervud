package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nervus-os/nervud/internal/admin"
	"github.com/nervus-os/nervud/internal/adminwire"
	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/authority/systemd"
	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/control"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/health"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/ipc"
	"github.com/nervus-os/nervud/internal/kernel"
	"github.com/nervus-os/nervud/internal/logging"
	"github.com/nervus-os/nervud/internal/motiongate"
	"github.com/nervus-os/nervud/internal/operation"
	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/pkgregistry"
	"github.com/nervus-os/nervud/internal/power"
	"github.com/nervus-os/nervud/internal/preflight"
	"github.com/nervus-os/nervud/internal/resource"
	"github.com/nervus-os/nervud/internal/resourcedir"
	"github.com/nervus-os/nervud/internal/safety"
	"github.com/nervus-os/nervud/internal/scheduler"
	"github.com/nervus-os/nervud/internal/service"
	"github.com/nervus-os/nervud/internal/transfer"
)

// safetyTripAdapter 把 service.SafetyEscalator 接到 safety.Module: Vital 组件熔断
// 时触发一次 Safety 锁存. 用 ReasonSupervisorEscalation - 监督者升级触发正是
// 一个关键组件反复崩溃, 由 service 监督链升级为停机的语义.
// 用适配器而不是让 service import safety, 是为了不把 safety 的 ReasonCode 语义渗进
// service 包
type safetyTripAdapter struct{ s *safety.Module }

func (a safetyTripAdapter) Trip() { a.s.Trip(safety.ReasonSupervisorEscalation) }

func main() {
	// 启动参数部分 (生产环境无)
	// 控制面 IPC 入口. 生产镜像固定为 /run/nervus/nervud.sock
	// flag 仅用于开发阶段
	sockPath := flag.String("sock", "/run/nervus/nervud.sock", "IPC socket path")
	transferSockPath := flag.String("transfer-sock", transfer.DefaultSockPath,
		"high-throughput transfer socket path")
	// 管理通道 UDS (root-only), 供 nervusctl 触发装包/卸载/权限授撤. 它必须与
	// App 控制面分开, 因为 App 控制面只接受 App 段 UID, root 运维工具无法连接
	adminSockPath := flag.String("admin-sock", adminwire.DefaultSockPath, "privileged admin channel socket path")
	logLevel := flag.String("log-level", "info", "Log level: debug/info/warn/error")
	// 仅供开发机 (缺 CAP_SYS_NICE 的 Linux 环境) 使用: 允许实时优先级设置失败后降级运行
	// 生产环境禁用, 缺 CAP_SYS_NICE 的 Linux 直接退出
	allowSchedDegrade := flag.Bool("dev-allow-sched-degrade", false,
		"[DEV] Allow real-time priority setting failure to downgrade to normal priority")
	// 仅供开发机: 跳过 文件系统 preflight. 生产镜像必须执行, 缺路径/权限不符即 fatal;
	// 开发机没有 /usr/libexec/nervus 等只读镜像路径, 需显式跳过才能起来
	skipPreflight := flag.Bool("dev-skip-preflight", false,
		"[DEV] Skip the filesystem preflight self-check (production must run it)")
	// 仅供开发机: 没有内嵌平台根时, 用系统包 manifest.sig 里内嵌的公钥当信任锚.
	// 验签, key_id 与 digest 仍然全部照做, 放松的只有"这把钥匙是否由平台根授权".
	// 不开它的话, 开发构建下每个系统包都 fail-closed 到 Ordinary, 而
	// perm.service.register 要 OEM, 于是任何导出公共接口的系统服务都注册不了
	devTrustSystemPackages := flag.Bool("dev-trust-system-packages", false,
		"[DEV] Anchor system-image packages on their own embedded signer keys (no platform root)")
	// 审计目录. 生产固定 /var/lib/nervus/audit (由 preflight 建好并设成 0700).
	//
	// 开发机上那个路径未必可写, 而"审计打不开就起不来"这条不退让成静默
	// 降级 - 一个跑着但不记审计的系统比一个起不来的更糟. 给一个显式开关,
	// 而不是让它在某些环境下悄悄变成只写 slog.
	auditDir := flag.String("audit-dir", audit.DefaultDir, "audit chain directory")
	flag.Parse()

	logger, closeLog := newLogger(*logLevel)
	slog.SetDefault(logger)

	// 根 context: 绑定 SIGINT/SIGTERM. 收到信号 -> ctx 取消 -> Kernel 反序关闭
	// systemd 是 nervud 的进程生命周期执行引擎; 停机由它发信号触发
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 第一次信号触发优雅停机后, 恢复默认信号行为, 让第二次信号能强制终止
	// 进程. 否则若优雅停机卡住, 后续 SIGTERM/SIGINT 仍被 NotifyContext 接管而
	// 无任何效果, 运维只剩 SIGKILL 一条路. 这给一个 收尾卡死时的逃生口
	go func() {
		<-ctx.Done()
		stop()
	}()

	// 把逻辑放进 run 是为了能用 return error - main 里一旦 os.Exit, defer 不会执行
	err := run(ctx, *sockPath, *transferSockPath, *adminSockPath, *auditDir,
		*allowSchedDegrade, *skipPreflight, *devTrustSystemPackages, logger)
	if err != nil {
		logger.Error("nervud exited", "err", err)
	} else {
		logger.Info("nervud stopped")
	}

	// 在 os.Exit 之前排空异步日志. closeLog 自带 flush 超时: 即便 stderr 已经
	// 完全卡死, 它也会在上限内返回, 退出路径不会被日志二次卡住.
	// 这两条日志都在 closeLog 之前写入 (异步入队), 关闭时一并排空
	if n := closeLog(); n > 0 {
		// 用同步的裸 handler 补记一笔丢弃计数: 此刻异步 writer 已停,
		// 这行必须走一条不依赖它的路径, 否则自己就被丢掉了
		slog.New(slog.NewTextHandler(os.Stderr, nil)).
			Warn("nervud: some log lines were dropped under back-pressure", "dropped", n)
	}

	if err != nil {
		os.Exit(1)
	}
}

// logQueueDepth 是异步日志队列能暂存的条数
//
// 512 条足以吸收突发 (启动期各模块一起打日志, fatal 时的密集记录),
// 又不至于占太多内存. 超过即丢弃并计数, 绝不阻塞写日志的一方
const logQueueDepth = 512

// newLogger 构造异步, 非阻塞的日志器
//
// 返回的第二个值是关闭函数: 它排空并停掉后台 writer, 返回被丢弃的日志条数.
// 必须在进程退出前调用一次. TextHandler 底层的 writer 是 AsyncWriter, 因此
// RT Lane, fatal 和停机路径写日志时都不会被慢 stderr 阻塞
func newLogger(level string) (*slog.Logger, func() uint64) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	aw := logging.NewAsyncWriter(os.Stderr, logQueueDepth)
	h := slog.NewTextHandler(aw, &slog.HandlerOptions{Level: lv})
	closeFn := func() uint64 {
		// 先 Close 再读计数: Close 关掉 stop 通道后, Write 不再走丢弃分支
		//  (改为同步直写), 因此关闭后的计数才是最终值
		_ = aw.Close()
		return aw.Dropped()
	}
	return slog.New(h), closeFn
}

// laneStopTimeout 是等待全部实时 Lane 退出的上限时间
// 超时即放弃等待并强制退出进程
// 报错退出 靠 systemd 重启, 生产环境5次启动失败, 应强制系统重启
// MCU (微控制器) 的安全机制 用于内核退出后的兜底
const laneStopTimeout = 2 * time.Second

// run 完成内核装配并阻塞运行, 直到 ctx 被取消或某个模块启动失败
// 具体的装配步骤拆到下面的 assemble, 让装配与运行/收尾分层清晰
//
// 关闭顺序
//
// # SIGTERM
//
// -> Kernel.stopAll 反序停模块 (IPC 最先关, audit 最后关)
// -> k.Run 返回
// -> sched.Shutdown 取消 lane ctx 并 join (下面的 defer)
// -> run 返回, 进程退出
//
// Lane 不监听信号 ctx, 它由 Scheduler 自己的 ctx 控制
// 否则 Lane 与 Kernel 会被同一个信号并行唤醒, 谁先退出不确定, Lane 的收尾
// 逻辑 (撤权, 刹停确认, 审计落盘) 可能在进程结束时被截断
// Lane 是最底层基建, 因此在所有模块停完之后才回收
func run(
	ctx context.Context,
	sockPath, transferSockPath, adminSockPath, auditDir string,
	allowSchedDegrade, skipPreflight, devTrustSystemPackages bool,
	logger *slog.Logger,
) (err error) {
	sched := scheduler.New(logger, allowSchedDegrade)

	// defer 保证无论装配失败还是正常停机, Lane 都会被取消并等待回收.
	// Lane 回收失败 (撤权/刹停确认/审计落盘没跑完) 必须反映到退出码,
	// 否则 systemd 看到 exit 0, 以为一切干净 - 用命名返回值 err 把它带出去
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), laneStopTimeout)
		defer cancel()
		if serr := sched.Shutdown(sctx); serr != nil {
			logger.Error("scheduler: lane not exited within timeout", "err", serr)
			if err == nil {
				err = fmt.Errorf("scheduler shutdown: %w", serr)
			}
		}
	}()

	k, cleanup, aerr := assemble(
		ctx, sched, sockPath, transferSockPath, adminSockPath, auditDir,
		skipPreflight, devTrustSystemPackages, logger)
	if aerr != nil {
		return aerr
	}
	// cleanup 关闭 systemd D-Bus 连接等设施资源. 它在 k.Run 返回后 (全部模块已停,
	// 含用到 spawner 的 service 模块) 执行, 早于上面的 scheduler defer (后进先出)
	defer cleanup()

	// Run 阻塞: 依次 Start 全部模块, 任一失败即反序 Stop 已启动的并返回错误
	// 全部成功后等待 ctx.Done, 再反序 Stop
	return k.Run(ctx)
}

// assemble 为 启动序列创建地基与模块 函数, 并登记到 Kernel
//
// 新模块加在这
// k.Register(...), Kernel 和其它模块都不用改
// 返回 error 表示装配阶段就已失败, 内核启动将会终止
func assemble(
	ctx context.Context,
	sched *scheduler.Scheduler,
	sockPath, transferSockPath, adminSockPath, auditDir string,
	skipPreflight, devTrustSystemPackages bool,
	logger *slog.Logger,
) (*kernel.Kernel, func(), error) {
	// cleanup 汇集设施级需要在停机时释放的资源 (当前只有 systemd D-Bus 连接).
	// 始终非 nil, 装配任一步失败时也安全可调用
	var closers []func()
	cleanup := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	// 文件系统 preflight: 在任何设施/模块构造之前执行. 只读镜像区不符即 fatal,
	// 可写区 (/var/lib/nervus/*, /run/nervus) 缺失则建, 权限不符则修. 它是内核给
	// 自己的地基做的开机自检, 必须先于 audit/authority/pkgregistry 的任何落盘发生
	if !skipPreflight {
		if err := preflight.Run(preflight.DefaultConfig(logger)); err != nil {
			return nil, cleanup, err
		}
	} else {
		logger.Warn("preflight: SKIPPED (dev-skip-preflight) - never in production")
	}

	// 设施层 构造即可用
	//
	// 装配顺序 = 依赖顺序, 与 Kernel 的启停顺序无关
	//
	// 审计: append-only 的哈希链文件 + slog 镜像.
	//
	// 打不开就起不来. 一个跑着但不记审计的系统比一个起不来的更糟 -
	// 前者会让人以为有审计, 而事后什么都查不到.
	//
	// 不注册成 Module: Module 的 Stop 在反序停机链里, 而审计必须活到
	// 最后一条停机记录写完之后. 用 defer 关, 它排在 cleanup 之后执行.
	aud, err := audit.NewFileRecorder(audit.FileConfig{
		Dir: auditDir,
		Log: logger,
	})
	if err != nil {
		return nil, cleanup, err
	}
	closers = append(closers, func() {
		if n := aud.Dropped(); n > 0 {
			// 丢弃意味着链上有缺口. 它已经作为 ChainGap 落进文件, 这里再报
			// 一次是为了让运维在 journal 里直接看见, 不必去读审计文件.
			logger.Warn("audit: records were dropped under back-pressure", "dropped", n)
		}
		if cerr := aud.Close(); cerr != nil {
			logger.Error("audit: close", "err", cerr)
		}
		// Close 之后再读: 它会补写终结记录并做最后一次 fsync, 这两笔都要算进去.
		//
		// records/syncs 的比值说明批量的实际效果. 两者接近说明几乎每条都是
		// Denied - 那不是配置问题, 是有什么在被反复拒绝, 值得去看.
		records, syncs := aud.Stats()
		logger.Info("audit: closed", "records", records, "syncs", syncs)
	})

	// systemd D-Bus 连接: 起进程 (StartSandboxedProcess) 的后端.
	// 连不上 (开发机无 D-Bus / 权限不足) 时 fail-closed: spawner=nil, authority 的
	// 起进程操作返回 ErrUnsupportedPlatform, 但装包/删树/设属主等非进程操作仍可用.
	// 与 trust store 同一取舍 - 缺失能力就退化, 绝不假装成功
	var spawner authority.UnitManager
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	sdConn, sderr := systemd.Dial(dialCtx)
	dialCancel()
	if sderr != nil {
		logger.Warn("systemd: dbus unavailable; process launch disabled", "err", sderr)
	} else {
		spawner = sdConn
		closers = append(closers, func() { _ = sdConn.Close() })
	}

	auth, err := authority.New(authority.Config{
		Auditor: aud,
		Log:     logger,
		Spawner: spawner,
		// Invariants 留空 = DefaultInvariants, 即生产安全值
		// 开发机想改 DataRoot 也不要加 flag, 因为生产二进制不能暴露
		// 可改变目录所有权与权限校验基线的开关
	})
	if err != nil {
		return nil, cleanup, err
	}

	// Scheduler - 由 run 创建并持有 (它负责 Lane 的取消与 join), 这里只使用
	//
	// 多线程 + 绑 Linux 线程设优先级 部分
	//
	// 实现方法
	//  用 runtime.LockOSThread 把某个 goroutine 钉死在一个专属线程上, 让 Go 不再搬动它, 也不往这个线程塞别的 goroutine
	//  再对这个线程调用 sched_setscheduler(2) 设策略与优先级
	//
	// scheduler.SpawnDedicated 把线程绑定和调度设置放进同一个生命周期边界
	// 实时调度是 Linux 独有. 非Linux无法启动内核. allowSchedDegrade 后为了调试可以特殊允许

	// motion epoch 与 Safety latch 必须放在同一个原子核心中, 避免状态与世代号撕裂
	// main 构造一次, 注入 safety 与 control同一个实例, 二者共享同一撤销世代号:
	// safety 在触发时锁存并递增, control 在 lease 生命周期事件上递增, 谁都不拥有它.
	// 三条 RT Lane (Stop FIFO 95 / Supervisor FIFO 90 / Control RR 40) 由各自模块自持
	//  (在 Start 里 spawn, Stop 里停), 不在这里挂占位 Lane.
	gate := motiongate.New()

	// 模块. 注册顺序 = 启动顺序, Kernel 关闭时反序执行
	// 每个模块在 New(...) 时接收它需要的窄接口依赖 (而不是全局单例)

	k := kernel.New(logger)

	// auth 以窄接口注入 (接口由消费者包定义, *Gate 隐式满足), 不把
	// *authority.Gate 整个传下去; 拿到全部方法的模块越少, Gate 的收敛作用越强
	//  例: pkgregistry 只需要装包能力, 就只定义并接收
	//  type PackageInstaller interface {
	//  InstallVerifiedPackage(context.Context, authority.Subject,...) error
	//  }
	//
	// identity.Registry 目前还没有 Module 外壳 (没有 Name/Start/Stop), 暂时
	// 只作为一个可用的库直接 New 出来, 传给 pkgregistry 做全量投影的接收方;
	// 等 identity 自己的 Module 外壳落地后, 这里改成从 Kernel 里取同一个实例
	idReg := identity.NewRegistry()

	// pkgregistry 自己的权威 Registry: 装包/卸载/启动扫描的全量状态只有这一份,
	// 不与 Module 分开持有, 否则两个实例会产生不可见的状态分叉
	pkgReg := pkgregistry.NewRegistry()

	// One immutable catalog snapshot is shared by package loading, endpoint
	// resolution, permissions, resources, and the IPC method gate. New Provider
	// interfaces and methods enter through signed artifacts; none of these
	// consumers keeps a capability-specific fallback table.
	definitions, err := catalog.NewDefaultRegistry()
	if err != nil {
		return nil, cleanup, fmt.Errorf("create definition catalog: %w", err)
	}
	permReg := permission.NewRegistry(definitions)

	transferMgr, err := transfer.New(transfer.Config{
		SockPath: transferSockPath,
		Log:      logger,
	})
	if err != nil {
		return nil, cleanup, err
	}
	// 运行期授予状态需要持久化并与 GrantUser 危险权限的撤销联动
	// 需要 control 作为 LeaseRevoker, 而 ctl 在下面才构造 - SetGrantStore 因此下移到
	// ctl 构造之后调用 (见该处), 这里先不接线, 避免用 nil revoker 载入一次又要重设

	// IPC 最后注册: 对外开门之前 Identity/Permission/Safety 必须先就绪,
	// 避免出现未受权限访问的窗口期.
	// 信任根: 内嵌平台根验证 /usr/share/nervus/trust 下的 bundle.
	// 加载失败 (开发构建缺内嵌根, bundle 缺失或验不过) 不阻断启动, 而是 fail-closed:
	// 传入零值 TrustStore - developer 自签仍可验证, platform/oem 一律拒绝, 动态安装
	// 只能拿 Ordinary. 这与验不过就 fail-closed, 绝不假装验证通过一致
	trustStore, terr := pkgregistry.LoadTrustStore(pkgregistry.DefaultTrustDir)
	if terr != nil {
		logger.Warn("pkgregistry: trust store unavailable; non-Ordinary trust disabled", "err", terr)
		// 开发降级: 用系统包自带的内嵌公钥当锚. 只在真的没有可用信任库时才尝试 -
		// 一旦生产信任库加载成功, 这个开关就没有任何效果, 不存在"用 flag 覆盖掉
		// 已验证信任根"的路径
		if devTrustSystemPackages {
			devStore, derr := pkgregistry.LoadDevTrustStore(
				pkgregistry.DefaultSystemPackagesDir, logger)
			if derr != nil {
				logger.Warn("pkgregistry: dev trust anchors unavailable; staying fail-closed",
					"err", derr)
			} else {
				trustStore = devStore
				logger.Warn("pkgregistry: DEV TRUST ACTIVE (dev-trust-system-packages) - never in production")
				// 审计而不只是日志: 这条改变了整机的信任裁决前提, 必须留在
				// 不受日志级别过滤的通道里
				aud.Record(ctx, audit.Event{
					Action:  "pkgregistry.DevTrustAnchors",
					Subject: "kernel",
					Detail:  "system-image packages anchored on embedded signer keys (no platform root)",
				})
			}
		}
	}
	pkgMod := pkgregistry.New(auth, idReg, permReg, pkgReg, definitions, trustStore, aud, logger,
		pkgregistry.DefaultRegistryStateDir, pkgregistry.DefaultSystemPackagesDir,
		authority.DefaultInvariants().PackageRoot, authority.DefaultInvariants().DataRoot,
	)
	k.Register(pkgMod)                  // Package Registry + 安装裁决
	k.Register(permission.New(permReg)) // capability 执法: Grant 投影由 pkgregistry 推送

	// Resource lookup reads the same catalog revision used by endpoint routing.
	resMod := resource.New(definitions)
	k.Register(resMod)

	// HUMAN/AI ControlLease + deadman + Control Lane(RR 40). 读/递增与 safety 同一个 gate.
	// 注册在 safety 之前 = 启动更早, 关闭更晚: 关停时 safety 先收工, control 最后撤租.
	//
	// 构造顺序也是依赖顺序: safety 需要它作为 LeaseRevoker, 而 control 不依赖 safety
	//  (deadman 失效只撤租 + 递增 epoch, 不锁存 Safety), 因此装配单向无环.
	ctl := control.New(sched, gate, aud, logger, control.DefaultPolicy())
	k.Register(ctl)

	// ctl 就绪后接线运行期授予状态: stateDir 持久化 + revoker=ctl. 撤销 motion 组权限时
	// permission 经该 revoker 调 ctl.RevokeByPackage 撤该包的执行器租约 (control 侧递增
	// motion epoch. SetGrantStore 之所以放在这里而不是 permReg 构造处, 是因为它
	// 需要 ctl - permReg 先构造 (pkgregistry 装配裁决要它), ctl 后构造, 故两段式接线.
	// AcquireControl/ReleaseControl 已由 IPC 接到同一个 ctl, 因此撤权会立即使现有
	// wire lease 失效, 而不是只影响下一次申请.
	permReg.SetGrantStore(pkgregistry.DefaultRegistryStateDir, ctl, aud)

	// Safety Gate + Stop Lane(FIFO 95) + Supervisor(FIFO 90): 模块自持两条 RT Lane.
	// 必须在 IPC 之前就绪 (对外开门前 Safety 须先武装). v1: 无真实 Provider, 投递用
	// NopPath, 上报用 NopReports; LeaseRevoker 接 control - motion epoch 递增仍是主
	// 撤销手段, ctl.RevokeAll 只负责清掉 lease 对象本身 (它不再叠加递增 epoch).
	safetyMod := safety.New(
		sched, gate, aud, logger,
		safety.DefaultContract(), safety.NopPath(), safety.NopReports(), ctl,
	)
	k.Register(safetyMod)

	// Service Manager: 把 Registry 里 enabled 的组件经 authority -> systemd 拉起成沙箱
	// 进程, 监视崩溃并按 criticality 分级处置, 并维护 unit -> 组件 反查索引解锁
	// ipc.verifyComponent. 注册在 safety 之后, ipc 之前: 启动方向
	// Safety 先武装, 外部进程才允许跑; 关闭反序 ipc -> service -> safety, 先停接客, 再停
	// 外部进程 (不再有运动指令源), 最后停 safety
	svcMgr := service.New(auth, pkgReg, permReg, safetyTripAdapter{safetyMod}, aud, logger,
		authority.DefaultInvariants())
	// 装包服务额外可写 staging 根: nervud 在那底下给它建 stage-* 目录让它解包,
	// 而沙箱的 ProtectSystem=strict 让整个文件系统只读. 这是唯一一条这类例外,
	// 放在装配处显式写出来, 别处不再有第二个地方能给出可写路径.
	//
	// 谁能拿到由 perm.pkg.admin 决定, 不由包名决定 - 内核不认识任何具体的
	// Package ID, 判据与管理通道的准入是同一条.
	svcMgr.GrantStagingAccess(admin.DefaultStagingDir)
	// 服务间共享区: 每个包在两个根下各有一个属主为自己, 0755 的子目录.
	// preflight 建根, pkgregistry 的启动扫描按包建子目录, service 把本包那个
	// 子目录放进 ReadWritePaths. 三处用的是同一份 Invariants, 路径不会分叉.
	pkgMod.SetSharedRoots(
		authority.DefaultInvariants().SharedRuntimeRoot,
		authority.DefaultInvariants().SharedPersistRoot,
	)
	k.Register(svcMgr)

	// Health 聚合器: 现读 safety/control/service 三个权威源合成整机一句话健康档位.
	// 注册在 safety/control/service 都构造之后, endpoint/ipc 之前 - 它依赖这三者已
	// 构造出实例 (不依赖其 Start, Report 现读现算).
	//
	// 缺口 (交收尾同学): *service.Manager 目前未实现health.ServiceObserver 要求的
	// Instances []service.Instance, 无法作为第三个观察者注入. 这里第三参传 nil,
	// 避免为装配临时扩大 service 的接口; health 对 nil 观察者 fail-safe (该维度按零值参与
	// 判定, 且 deriveStatus 的 fail-closed 规则保证看不到 Safety永不误判 Healthy).
	// service 组件维度待 *service.Manager 补 Instances 后, 把 nil 换成 svcMgr 即可.
	healthMod := health.New(safetyMod, ctl, nil)
	k.Register(healthMod)

	// 把卸载/停用需要的外部协作者注入 pkgregistry: service 停组件; control 撤租.
	// 卸载 Package 时经 ctl.RevokeByPackage 撤销该包名下的执行器租约 (含 motion 则由
	// control 递增 motion epoch). IPC lease 已接线, 现有租约会在卸载流程中同步撤销.
	pkgMod.SetLifecycleHooks(svcMgr, ctl)

	// Endpoint 注册/解析/路由必须在 service 之后, IPC 之前注册,
	// 因为 Resolve 拉起 on-demand 组件时依赖 svcMgr.EnsureStarted
	epMod := endpoint.New(definitions, pkgReg, permReg, svcMgr, aud, logger)

	// 注册内建 endpoint: 由 nervud 自己实现, 不经外部 Service 的 Interface.
	//
	// Safety 的观察与 re-arm 天生长在内核里, 不可能由 Provider 提供 - 它们直接
	// 操作内核状态. 但 App 与恢复服务要用到, 而控制面上唯一的调用形态是
	// ResolveEndpoint -> Request -> Response.
	//
	// envelope.proto 堵死了"加一个新 body"这条路 ("不属于那八件事就应该做成
	// 某个 Interface 的 method"), 所以走内建 endpoint: 调用方用完全标准的
	// Resolve+Request 访问, 不知道也不需要知道对面是内核还是 Provider.
	//
	// 装配期注册失败是硬错误: 一个少了 Safety 恢复通道的系统起来了也不该被信任
	// - 机器一旦停机就再也解不开, 只能重启整个内核.
	if err := epMod.RegisterBuiltin(
		safety.BuiltinInterfaceID, 1, 0, safetyMod.BuiltinHandler(),
	); err != nil {
		return nil, cleanup, fmt.Errorf("register builtin %s: %w", safety.BuiltinInterfaceID, err)
	}
	logger.Info("endpoint: builtin registered", "interface", safety.BuiltinInterfaceID)

	// 整机电源 (有序重启/关机). 同样是内建: 真正执行的是 Authority Gate,
	// 只有 nervud 有那个权限, 不可能由外部 Provider 提供.
	//
	// 注册失败同样是硬错误: 一个起来了但关不掉的系统, 用户只能拔电,
	// 而拔电正是这条通道存在的目的 (避免非正常掉电损坏文件系统)
	powerMod := power.New(auth, logger)
	if err := epMod.RegisterBuiltin(
		power.BuiltinInterfaceID, 1, 0, powerMod.BuiltinHandler(),
	); err != nil {
		return nil, cleanup, fmt.Errorf("register builtin %s: %w", power.BuiltinInterfaceID, err)
	}
	logger.Info("endpoint: builtin registered", "interface", power.BuiltinInterfaceID)

	// 资源目录: Catalog 自己的只读视图, 补的是"有哪些设备"这个枚举缺口.
	// 没有它, App 只能靠反复 Resolve 试探, 而失败的 Resolve 分不清
	// "没有这个设备"和"有但我没权限".
	//
	// 注册失败同样是硬错误, 但理由与上面两条不同: 它不是安全通道, 而是
	// bootstrap 契约与本二进制不一致的信号 - 接口在 Catalog 里, handler
	// 却装不上, 说明两边已经漂移, 后面的任何 Resolve 结果都不再可信.
	resourceDirMod := resourcedir.New(definitions, logger)
	if err := epMod.RegisterBuiltin(
		resourcedir.BuiltinInterfaceID, 1, 0, resourceDirMod.BuiltinHandler(),
	); err != nil {
		return nil, cleanup, fmt.Errorf(
			"register builtin %s: %w", resourcedir.BuiltinInterfaceID, err)
	}
	logger.Info("endpoint: builtin registered", "interface", resourcedir.BuiltinInterfaceID)

	k.Register(epMod)

	// Operation Manager: 给机械臂轨迹/回零/移到位姿这类系统协调长任务一个由 nervud
	// 拥有的状态机与句柄. 注册在 endpoint 之后, ipc 之前: Resolve/Route
	// 就绪后 operation 才谈得上被 dispatch 创建, IPC 开门前状态机须已就绪. 窄接口注入
	// resource (resMod.Valid 校验 resource_handle) 与 audit.
	//
	// LeaseValidator 在 ipc 装配之后注入 (见下方 SetLeaseValidator 那一段):
	// 解开 wire lease 句柄需要 conn 的映射表, 而那住在 ipc 里.
	//
	// 这里先传 nil 不是遗留, 是构造顺序: operation 必须在 endpoint 之后,
	// ipc 之前注册 (Resolve/Route 就绪后 operation 才谈得上被 dispatch 创建,
	// IPC 开门前状态机须已就绪), 而 ipc 又要在 operation 之后才能构造.
	// 中间这一段里 lease 为 nil, 运动类 operation fail closed.
	opMod := operation.New(resMod, nil, aud, logger)
	k.Register(opMod)

	// The transfer manager owns the separate high-throughput Unix socket. It
	// starts before IPC accepts control calls and stops after IPC, so no control
	// route can issue a handle without a live data plane.
	k.Register(transferMgr)

	// IPC 控制面 UDS: 最后开门. 依赖上面全部就绪 (Identity/Permission/Safety/Service/
	// Endpoint). Components 接 svcMgr 解锁 verifyComponent; Endpoints 接 epMod 解锁
	// ResolveEndpoint/RegisterEndpoint/UnregisterEndpoint 与 Request 的 Route 查表
	// - 至此 App/Service 才真正握得上手
	ipcSrv, err := ipc.New(ipc.Config{
		SockPath:   sockPath,
		Log:        logger,
		Auditor:    aud,
		Invariants: authority.DefaultInvariants(),
		Identity:   idReg,
		Permission: permReg,
		Components: svcMgr,
		Endpoints:  epMod,
		// Leases 接通 AcquireControl/ReleaseControl (envelope 70-73). 在此之前
		// control 模块虽然完整, 却没有任何入口 - App 拿不到运动 lease.
		Leases: ctl,
		// Resources 让 AcquireControl 的 selector 能解析成 resource_handle,
		// 与 ResolveEndpoint 用同一张表, 同一套匹配规则. 空 selector 在 v2 里
		// 不再有隐式默认, 两条路径一起 fail closed.
		Resources: resMod,
		// Operations 接通长任务: 声明了 returns_operation 的方法在这里才谈得上
		// 被受理. 为 nil 时它们一律被拒 - 不是降级成普通调用, 那会让调用方
		// 拿到一个 OK 而机器还在动.
		Operations: opMod,
		Transfer:   transferMgr,
		// Launcher 接通 LaunchComponent (envelope 80/81): Launcher 点开一个 App,
		// 会话服务开机唤起桌面, 都走它. 在此之前唯一能拉起组件的路径是
		// endpoint.Resolve 拉起 on-demand 提供者, 于是"启动应用"只能伪装成
		// "解析接口" - 审计里两件事分不开, 且没有接口的纯 UI 应用根本启动不了.
		Launcher: svcMgr,
	})
	if err != nil {
		return nil, cleanup, err
	}
	// Runtime revocation must close matching Dispatch route tokens before it
	// scans Transfer records. IPC owns that coordination boundary; wiring the
	// raw Transfer manager here would leave a revoke-then-Begin race.
	permReg.SetPermissionRevoker(ipcSrv)
	// Install-grant removal may run inside a package transaction. Service only
	// records a supervisor stop intent on this hook; it never waits on systemd or
	// looks the package up while the transaction lock is held.
	permReg.SetInstallGrantRevoker(svcMgr)
	// USER_CONSENT changes also alter process sandbox mounts. This separate hook
	// is never called by permission.Replace, so a package transaction cannot wait
	// on systemd or accidentally restart a package while rolling back.
	permReg.SetRuntimePermissionProjector(svcMgr)
	ctl.SetLeaseObserver(ipcSrv)
	pkgMod.SetTransferRevoker(ipcSrv)
	if err := epMod.RegisterBuiltin(
		catalog.InterfaceTransferControl, 1, 0, ipcSrv.TransferBuiltinHandler(),
	); err != nil {
		return nil, cleanup, fmt.Errorf(
			"register builtin %s: %w", catalog.InterfaceTransferControl, err)
	}
	logger.Info("endpoint: builtin registered", "interface", catalog.InterfaceTransferControl)

	// Operation 的三处回填必须在 ipc 构造之后: 校验器与内建 handler 都住在
	// ipc 里, 而 operation 又必须在 ipc 之前注册 (IPC 开门前状态机须就绪).
	// 构造顺序把依赖变成了一个环, 用装配期回填打开它.
	//
	// 顺序有意义: 先装 handler (它建立 operationWire), 再注册 endpoint
	// 拿到句柄, 最后才接事件旁路 - 旁路要用那个句柄做扇出键.
	opMod.SetLeaseValidator(ipcSrv.OperationLeaseValidator())
	if err := epMod.RegisterBuiltin(
		catalog.InterfaceOperationControl, 1, 0, ipcSrv.OperationBuiltinHandler(),
	); err != nil {
		return nil, cleanup, fmt.Errorf(
			"register builtin %s: %w", catalog.InterfaceOperationControl, err)
	}
	if err := epMod.RegisterBuiltinSubscriber(
		catalog.InterfaceOperationControl, 1, ipcSrv.OperationSubscribeAdmitter(),
	); err != nil {
		return nil, cleanup, fmt.Errorf(
			"register builtin subscriber %s: %w", catalog.InterfaceOperationControl, err)
	}
	operationEndpointID, ok := epMod.BuiltinEndpointID(catalog.InterfaceOperationControl, 1)
	if !ok {
		return nil, cleanup, fmt.Errorf(
			"builtin %s has no endpoint id after registration",
			catalog.InterfaceOperationControl)
	}
	ipcSrv.SetOperationEndpointID(operationEndpointID)
	opMod.SetEventObserver(ipcSrv.OperationEventObserver())
	logger.Info("endpoint: builtin registered", "interface", catalog.InterfaceOperationControl)

	k.Register(ipcSrv)

	// 特权管理通道 (root-only UDS): 供 nervusctl 触发装包/卸载/停用启用/权限授撤.
	// 注册在 ipc 之后 = 启动更晚, 关闭更早: 关停时先停管理面 (不再接受新的装包/改权限
	// 命令), 再停 App 控制面. 它驱动同一个进程内的 pkgregistry.Module / permission
	// .Registry, 绝不另开第二个写者, 避免权威状态分叉. AdminUID 取 nervud 自身
	// euid (生产为 0/root) - 只有运行 nervud 的运维身份可发命令, 配合 socket 0600.
	// StagingRoot 留空 = admin.DefaultStagingDir (/var/lib/nervus/staging, 由 preflight
	// 建好, 与 PackageRoot 同一文件系统, 安装期 renameat2 才不跨盘)
	// 装包服务需要连管理通道才能替 App 装包 (App 不可能是 root, 而系统服务
	// 跑在 App UID 段).
	//
	// 这里不出现任何 Package ID. 谁能连由 admin.PermissionPackageAdmin
	//  (perm.pkg.admin) 决定, admin 自己在 Start 里按权限解析 - 它注册在
	// pkgregistry 之后, 那时启动扫描已完成, UID 已分配, 权限已裁决.
	// 装配期这三样都还不存在, 在这里判定写出来的会是死代码.
	adminSrv, err := admin.New(admin.Config{
		SockPath:    adminSockPath,
		AdminUID:    uint32(os.Geteuid()),
		Packages:    pkgMod,
		Registry:    pkgReg,
		Permissions: permReg,
		Auditor:     aud,
		Log:         logger,
	})
	if err != nil {
		return nil, cleanup, err
	}
	k.Register(adminSrv)

	return k, cleanup, nil
}
