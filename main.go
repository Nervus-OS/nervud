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

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/kernel"
	"github.com/nervus-os/nervud/internal/logging"
	"github.com/nervus-os/nervud/internal/motiongate"
	"github.com/nervus-os/nervud/internal/pkgregistry"
	"github.com/nervus-os/nervud/internal/safety"
	"github.com/nervus-os/nervud/internal/scheduler"
)

func main() {
	// 启动参数部分（生产环境无）
	// 控制面 IPC 入口。生产镜像固定为 /run/nervus/nervud.sock
	// flag 仅用于开发阶段
	sockPath := flag.String("sock", "/run/nervus/nervud.sock", "IPC socket path")
	logLevel := flag.String("log-level", "info", "Log level：debug/info/warn/error")
	// 仅供开发机（缺 CAP_SYS_NICE 的 Linux 环境）使用：允许实时优先级设置失败后降级运行
	// 生产环境禁用，缺 CAP_SYS_NICE 的 Linux 直接退出
	allowSchedDegrade := flag.Bool("dev-allow-sched-degrade", false,
		"[DEV] Allow real-time priority setting failure to downgrade to normal priority")
	flag.Parse()

	logger, closeLog := newLogger(*logLevel)
	slog.SetDefault(logger)

	// 根 context：绑定 SIGINT/SIGTERM。收到信号 -> ctx 取消 -> Kernel 反序关闭
	// systemd 是 nervud 的进程生命周期执行引擎；停机由它发信号触发
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 第一次信号触发优雅停机后，恢复默认信号行为，让【第二次】信号能强制终止
	// 进程。否则若优雅停机卡住，后续 SIGTERM/SIGINT 仍被 NotifyContext 接管而
	// 无任何效果，运维只剩 SIGKILL 一条路。这给一个 收尾卡死时的逃生口
	go func() {
		<-ctx.Done()
		stop()
	}()

	// 把逻辑放进 run() 是为了能用 return error —— main 里一旦 os.Exit，defer 不会执行
	err := run(ctx, *sockPath, *allowSchedDegrade, logger)
	if err != nil {
		logger.Error("nervud exited", "err", err)
	} else {
		logger.Info("nervud stopped")
	}

	// 在 os.Exit 之前排空异步日志。closeLog 自带 flush 超时：即便 stderr 已经
	// 完全卡死，它也会在上限内返回，退出路径不会被日志二次卡住。
	// 这两条日志都在 closeLog 之前写入（异步入队），关闭时一并排空
	if n := closeLog(); n > 0 {
		// 用同步的裸 handler 补记一笔丢弃计数：此刻异步 writer 已停，
		// 这行必须走一条不依赖它的路径，否则自己就被丢掉了
		slog.New(slog.NewTextHandler(os.Stderr, nil)).
			Warn("nervud: some log lines were dropped under back-pressure", "dropped", n)
	}

	if err != nil {
		os.Exit(1)
	}
}

// logQueueDepth 是异步日志队列能暂存的条数
//
// 512 条足以吸收突发（启动期各模块一起打日志、fatal 时的密集记录），
// 又不至于占太多内存。超过即丢弃并计数，绝不阻塞写日志的一方
const logQueueDepth = 512

// newLogger 构造异步、非阻塞的日志器
//
// 返回的第二个值是关闭函数：它排空并停掉后台 writer，返回被丢弃的日志条数。
// 必须在进程退出前调用一次。TextHandler 底层的 writer 是 AsyncWriter，因此
// 任何路径（RT Lane、fatal、停机）写日志都不会被慢 stderr 阻塞（见 internal/logging）
func newLogger(level string) (*slog.Logger, func() uint64) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	aw := logging.NewAsyncWriter(os.Stderr, logQueueDepth)
	h := slog.NewTextHandler(aw, &slog.HandlerOptions{Level: lv})
	closeFn := func() uint64 {
		// 先 Close 再读计数：Close 关掉 stop 通道后，Write 不再走丢弃分支
		// （改为同步直写），因此关闭后的计数才是最终值
		_ = aw.Close()
		return aw.Dropped()
	}
	return slog.New(h), closeFn
}

// laneStopTimeout 是等待全部实时 Lane 退出的上限时间
// 超时即放弃等待并强制退出进程
// 报错退出 靠 systemd 重启，生产环境5次启动失败，应强制系统重启
// MCU （微控制器） 的安全机制 用于内核退出后的兜底
const laneStopTimeout = 2 * time.Second

// run 完成内核装配并阻塞运行，直到 ctx 被取消或某个模块启动失败
// 具体的装配步骤拆到下面的 assemble()，让「装配」与「运行/收尾」分层清晰
//
// 关闭顺序
//
// SIGTERM
//
//	-> Kernel.stopAll 反序停模块（IPC 最先关、audit 最后关）
//	-> k.Run 返回
//	-> sched.Shutdown 取消 lane ctx 并 join（下面的 defer）
//	-> run 返回，进程退出
//
// Lane 不监听信号 ctx，它由 Scheduler 自己的 ctx 控制
// 否则 Lane 与 Kernel 会被同一个信号并行唤醒，谁先退出不确定，Lane 的收尾
// 逻辑（撤权、刹停确认、审计落盘）可能在进程结束时被截断
// Lane 是最底层基建，因此在所有模块停完之后才回收
func run(ctx context.Context, sockPath string, allowSchedDegrade bool, logger *slog.Logger) (err error) {
	sched := scheduler.New(logger, allowSchedDegrade)

	// defer 保证无论装配失败还是正常停机，Lane 都会被取消并等待回收。
	// Lane 回收失败（撤权/刹停确认/审计落盘没跑完）必须反映到退出码，
	// 否则 systemd 看到 exit 0、以为一切干净——用命名返回值 err 把它带出去
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

	k, aerr := assemble(ctx, sched, sockPath, logger)
	if aerr != nil {
		return aerr
	}

	// Run 阻塞：依次 Start 全部模块，任一失败即反序 Stop 已启动的并返回错误
	// 全部成功后等待 ctx.Done()，再反序 Stop
	return k.Run(ctx)
}

// assemble 为 启动序列创建地基与模块 函数，并登记到 Kernel
//
// 新模块加在这
// k.Register(...)，Kernel 和其它模块都不用改
// 返回 error 表示装配阶段就已失败，内核启动将会终止
func assemble(ctx context.Context, sched *scheduler.Scheduler, sockPath string, logger *slog.Logger) (*kernel.Kernel, error) {
	// 设施层 构造即可用
	//
	// 装配顺序 = 依赖顺序，与 Kernel 的启停顺序无关
	//
	// audit 现为设施形态（Record 落 slog）；将来若需要落盘 writer 的启停
	// 同时注册成 Module 且放最后一位 = 最后关闭，保证关停过程也有审计
	aud := audit.New(logger)

	auth, err := authority.New(authority.Config{
		Auditor: aud,
		Log:     logger,
		// Invariants 留空 = DefaultInvariants()，即生产安全值
		// 开发机想改 DataRoot 也【不要】加 flag：生产二进制里不允许存在
		// 能松动安全地板的开关（参照 allowSchedDegrade 的反面教训边界）
	})
	if err != nil {
		return nil, err
	}

	// Scheduler —— 由 run() 创建并持有（它负责 Lane 的取消与 join），这里只使用
	//
	// 多线程 + 绑 Linux 线程设优先级 部分
	//
	// 实现方法
	//   用 runtime.LockOSThread() 把某个 goroutine 钉死在一个专属线程上，让 Go 不再搬动它、也不往这个线程塞别的 goroutine
	//   再对这个线程调用 sched_setscheduler(2) 设策略与优先级
	//
	// scheduler.SpawnDedicated() 封装了这两步（见 internal/scheduler）
	// 实时调度是 Linux 独有。非Linux无法启动内核。allowSchedDegrade 后为了调试可以特殊允许

	// motion epoch 与 Safety latch 的共享原子核心（见 internal/motiongate）。
	// main 构造一次并注入 safety；control 落地后注入【同一个】实例，二者共享同一撤销世代号。
	// 两条 Safety RT Lane（Stop Lane FIFO 95 / Supervisor FIFO 90）由 safety 模块自持
	// （在 Start 里 spawn、Stop 里停），不再在这里挂占位 Lane。
	gate := motiongate.New()

	// 模块。注册顺序 = 启动顺序，Kernel 关闭时反序执行
	// 每个模块在 New(...) 时接收它需要的窄接口依赖（而不是全局单例）

	k := kernel.New(logger)

	// auth 以【窄接口】注入（接口由消费者包定义，*Gate 隐式满足），不把
	// *authority.Gate 整个传下去；拿到全部方法的模块越少，Gate 的收敛作用越强
	//   例：pkgregistry 只需要装包能力，就只定义并接收
	//     type PackageInstaller interface {
	//         InstallVerifiedPackage(context.Context, authority.Subject, ...) error
	//     }
	//
	// identity.Registry 目前还没有 Module 外壳（没有 Name/Start/Stop），暂时
	// 只作为一个可用的库直接 New 出来，传给 pkgregistry 做全量投影的接收方；
	// 等 identity 自己的 Module 外壳落地后，这里改成从 Kernel 里取同一个实例
	idReg := identity.NewRegistry()

	// pkgregistry 自己的权威 Registry：装包/卸载/启动扫描的全量状态只有这一份，
	// 不与 Module 分开持有（见 internal/pkgregistry/module.go 顶部说明）
	pkgReg := pkgregistry.NewRegistry()

	// TODO(rewrite): 按 sec 2 逐个接入，从最基础往上叠。IPC 放最后：对外开门之前
	// Identity/Permission/Safety 须先就绪，避免出现 未受权限访问 的窗口期
	//   k.Register(identity.New(...))       // SO_PEERCRED、UID -> Package 映射
	//   k.Register(permission.New(...))     // capability 执法
	k.Register(pkgregistry.New(auth, idReg, pkgReg, aud, logger,
		pkgregistry.DefaultRegistryStateDir, pkgregistry.DefaultSystemPackagesDir,
		authority.DefaultInvariants().PackageRoot, authority.DefaultInvariants().DataRoot,
	)) // Package Registry + 安装裁决
	//   k.Register(service.New(auth, ...))  // App/Service 组件生命周期
	//   k.Register(endpoint.New(...))       // Endpoint 注册/解析/路由
	//   k.Register(resource.New(...))       // Resource Registry + Provider 绑定
	//   k.Register(control.New(gate, ...))  // HUMAN/AI ControlLease（读/递增同一个 gate）

	// Safety Gate + Stop Lane(FIFO 95) + Supervisor(FIFO 90)：模块自持两条 RT Lane。
	// 必须在 IPC 之前就绪（对外开门前 Safety 须先武装）。v1：无真实 Provider，投递用
	// NopPath、上报用 NopReports；LeaseRevoker 为 nil（靠 motion epoch 递增撤销）。
	k.Register(safety.New(
		sched, gate, aud, logger,
		safety.DefaultContract(), safety.NopPath(), safety.NopReports(), nil,
	))
	//   k.Register(ipc.New(sockPath, ...))  // 控制面 UDS，依赖上面全部就绪（含 Safety）
	_ = sockPath

	return k, nil
}
