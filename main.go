package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/kernel"
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

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	// 根 context：绑定 SIGINT/SIGTERM。收到信号 -> ctx 取消 -> Kernel 反序关闭
	// systemd 是 nervud 的进程生命周期执行引擎；停机由它发信号触发
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 把逻辑放进 run() 是为了能用 return error —— main 里一旦 os.Exit，defer 不会执行
	if err := run(ctx, *sockPath, *allowSchedDegrade, logger); err != nil {
		logger.Error("nervud exited", "err", err)
		os.Exit(1)
	}
	logger.Info("nervud stopped")
}

// 日志解析器
// 函数名：newLogger
// 参数：level，类型 string
// 返回：*slog.Logger
func newLogger(level string) *slog.Logger {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})
	return slog.New(h)
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
func run(ctx context.Context, sockPath string, allowSchedDegrade bool, logger *slog.Logger) error {
	sched := scheduler.New(logger, allowSchedDegrade)

	// defer 保证无论装配失败还是正常停机，Lane 都会被取消并等待回收
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), laneStopTimeout)
		defer cancel()
		if err := sched.Shutdown(sctx); err != nil {
			logger.Error("scheduler: lane not exited within timeout", "err", err)
		}
	}()

	k, err := assemble(ctx, sched, sockPath, logger)
	if err != nil {
		return err
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

	// TODO(rewrite): 换成 safety.Supervisor 的真实循环，并把这条 Lane 的所有权
	//   移交给 safety 模块（由它在 Start 里 spawn、Stop 里停）
	//   另外还要按 sec 6 起一条 PrioEmergencyStop(99) 的 Stop Lane（零堆分配热路径）
	if err := sched.SpawnDedicated("safety-supervisor",
		scheduler.PolicyFIFO, scheduler.PrioSafety,
		func(ctx context.Context) {
			<-ctx.Done() // 占位：收到停机信号即退出
		}); err != nil {
		return nil, err
	}

	// 模块。注册顺序 = 启动顺序，Kernel 关闭时反序执行
	// 每个模块在 New(...) 时接收它需要的窄接口依赖（而不是全局单例）

	k := kernel.New(logger)

	// auth 以【窄接口】注入（接口由消费者包定义，*Gate 隐式满足），不把
	// *authority.Gate 整个传下去；拿到全部方法的模块越少，Gate 的收敛作用越强
	//   例：pkgregistry 只需要装包能力，就只定义并接收
	//     type PackageInstaller interface {
	//         InstallVerifiedPackage(context.Context, authority.Subject, ...) error
	//
	//
	// TODO(rewrite): 按 sec 2 逐个接入，从最基础往上叠。IPC 放最后：对外开门之前
	// Identity/Permission/Safety 须先就绪，避免出现 未受权限访问 的窗口期
	//   k.Register(identity.New(...))       // SO_PEERCRED、UID -> Package 映射
	//   k.Register(permission.New(...))     // capability 执法
	//   k.Register(pkgregistry.New(auth, ...)) // Package Registry + 安装裁决
	//   k.Register(service.New(auth, ...))  // App/Service 组件生命周期
	//   k.Register(endpoint.New(...))       // Endpoint 注册/解析/路由
	//   k.Register(resource.New(...))       // Resource Registry + Provider 绑定
	//   k.Register(control.New(...))        // HUMAN/AI ControlLease + motion epoch
	//   k.Register(safety.New(sched, ...))  // Safety Gate + StopProgress（用上面的 sched 起 Lane）
	//   k.Register(ipc.New(sockPath, ...))  // 控制面 UDS，依赖上面全部就绪
	_ = sockPath
	_ = auth

	return k, nil
}
