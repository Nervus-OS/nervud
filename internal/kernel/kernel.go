// Package kernel 管理内核模块的有序启动与反序关闭
// 它只依赖 Module 接口，不 import 任何具体模块，以保证依赖单向
// Kernel 只认接口，装配细节留给 main，便于对生命周期做单测
package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Module 是所有内核模块的统一生命周期契约
//
// # Start 应快速返回：长期运行的循环自行开 goroutine
//
// 循环的退出只听 Stop，不听 Start(ctx) 的 ctx。若循环也监听信号 ctx，
// 它会与 stopAll 被同一个信号并行唤醒，谁先退出不确定，停机顺序就不再由
// 反序 Stop 唯一决定；模块的收尾逻辑（撤权、刹停确认、审计落盘）可能被截断
//
// # Stop 收到的 ctx 带有超时（见 defaultStopTimeout），实现应当尊重它并尽快返回
//
// 但 Kernel 不信任模块一定会遵守：即便 Stop 无视 ctx 永久卡住，Kernel 也会
// 在超时后放弃等待、继续关闭后续模块（见 stopModule）。一个卡死的模块不能连累
// 整条关闭序列 - 尤其是排在最后、负责落盘审计的那个
type Module interface {
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// FatalReporter 由 有后台循环、且循环可能不可恢复地失效 的模块实现
//
// 有后台循环的模块必须实现本接口。没有它，一个 accept 循环彻底失效的模块
// 会静默变成空壳：Start 早已成功返回，Stop 也从没被调用，Kernel 完全看不见，
// 而外部只观察到 服务在跑但不干活 这是最难诊断的一种故障
//
// 通道上出现一个非 nil error 即表示该模块已经不可恢复。Kernel 会据此
// 反序关闭全部模块并让 Run 返回错误，最终 main 非零退出、systemd 重启
//
// 通道应有缓冲且只写一次；模块不得因为没人读而阻塞在写上
type FatalReporter interface {
	Fatal() <-chan error
}

// defaultStopTimeout 是单个模块 Stop 的时间上限
//
// 逐模块计时而不是给整个关闭序列一个总预算：总预算会让排在后面的模块
// （也就是最底层、收尾最要紧的那些）因为前面的模块慢而被剥夺时间
const defaultStopTimeout = 5 * time.Second

type Kernel struct {
	log     *slog.Logger
	modules []Module

	// stopTimeout 单独成字段是为了让测试能压到毫秒级，
	// 而不必让用例真的等满生产超时
	stopTimeout time.Duration
}

func New(log *slog.Logger) *Kernel {
	return &Kernel{log: log, stopTimeout: defaultStopTimeout}
}

// Register 按调用顺序登记模块；启动顺序 = 注册顺序，关闭顺序 = 反序
// 只在 Run 之前调用（装配阶段），运行期不再增删
func (k *Kernel) Register(m Module) {
	k.modules = append(k.modules, m)
}

type moduleFailure struct {
	name string
	err  error
}

// Run 依次启动全部模块；任一启动失败则反序关闭已启动的模块并返回错误
// *请注意 启动失败后，不会 stop 启动失败的模块
//
// 启动与运行期都在监听两个停机来源：
//
//	ctx 取消     - SIGINT/SIGTERM，计划内停机，反序 Stop 后返回 nil
//	某模块报告致命错误 - 反序 Stop 后返回该错误，main 据此非零退出
//
// 关键点：fatal watcher 是逐模块安装的，且每启动一个模块前都重新检查这两个
// 来源。因此启动过程中若某个已就绪模块立刻 fatal、或此刻收到 SIGTERM，Kernel
// 会当场停止启动并回滚，而不是傻等把剩下的模块也启动完
func (k *Kernel) Run(ctx context.Context) error {
	// watchDone 让监视 goroutine 随 Run 一起退出，避免它们悬在已经没人读的
	// 模块通道上。两条返回路径都由 defer 覆盖
	watchDone := make(chan struct{})
	defer close(watchDone)

	// 容量 = 模块数：每个模块最多写一次，写入方永不阻塞，即使 Kernel 已经在
	// 走关闭流程、不再读这条通道
	fatal := make(chan moduleFailure, len(k.modules))

	started := make([]Module, 0, len(k.modules))

	for _, m := range k.modules {
		// 启动下一个之前，先看是不是已经该停了。放在循环顶部，让 启动期收到
		// SIGTERM 和 已就绪模块启动期 fatal 都能当场生效，而不是等全部启动完
		select {
		case <-ctx.Done():
			k.log.Info("shutdown requested during startup; rolling back", "started", len(started))
			if err := k.stopAll(started); err != nil {
				return fmt.Errorf("shutdown during startup completed with errors: %w", err)
			}
			return nil
		case f := <-fatal:
			k.log.Error("module failed during startup; rolling back",
				"module", f.name, "err", f.err, "started", len(started))
			return joinShutdown(fmt.Errorf("module %s failed at runtime: %w", f.name, f.err), k.stopAll(started))
		default:
		}

		k.log.Info("starting module", "module", m.Name())
		if err := m.Start(ctx); err != nil {
			k.log.Error("module failed to start; rolling back", "module", m.Name(), "err", err)
			return joinShutdown(fmt.Errorf("start %s: %w", m.Name(), err), k.stopAll(started))
		}
		started = append(started, m)

		// 立刻挂 watcher，不等全部启动完。晚挂一个模块的 watcher，就等于在启动
		// 剩余模块的那段时间里对它的 fatal 视而不见
		k.watchModuleFatal(m, fatal, watchDone)
	}
	k.log.Info("kernel ready", "modules", len(started))

	select {
	case <-ctx.Done():
		k.log.Info("shutdown signal received; shutting down")
		// 即便是计划内停机，收尾失败也必须反映到退出码：否则撤权、刹停确认、
		// 审计落盘失败时进程仍以 0 退出，systemd 完全看不见 - 这正是最需要
		// 被看见的一类失败
		if err := k.stopAll(started); err != nil {
			return fmt.Errorf("shutdown completed with errors: %w", err)
		}
		return nil

	case f := <-fatal:
		// 不做局部降级：半死的 TCB 比重启更危险。整体关停后让 systemd 重启，
		// 连续失败由 StartLimitAction=reboot 兜底
		k.log.Error("module reported a fatal error; shutting down kernel",
			"module", f.name, "err", f.err)
		// 致命错误是主因，但收尾失败也不该丢 - 一并 join，供离线分析
		return joinShutdown(fmt.Errorf("module %s failed at runtime: %w", f.name, f.err), k.stopAll(started))
	}
}

// joinShutdown 把主错误与收尾错误合并：主错误恒在，收尾错误有则附加
func joinShutdown(primary, stopErr error) error {
	if stopErr == nil {
		return primary
	}
	return errors.Join(primary, stopErr)
}

// watchModuleFatal 为单个模块安装致命错误监视 goroutine
//
// 不实现 FatalReporter、或 Fatal 返回 nil 的模块直接跳过 - 本接口是可选的，
// 没有后台循环的设施型模块不需要它
func (k *Kernel) watchModuleFatal(m Module, out chan<- moduleFailure, done <-chan struct{}) {
	fr, ok := m.(FatalReporter)
	if !ok {
		return
	}
	ch := fr.Fatal()
	if ch == nil {
		return
	}
	go func(name string) {
		select {
		case err, open := <-ch:
			// 通道被关闭（open=false）不代表故障：模块可能只是在收尾时关掉了它。
			// 只有真的收到一个非 nil error 才算致命
			if open && err != nil {
				select {
				case out <- moduleFailure{name: name, err: err}:
				case <-done:
				}
			}
		case <-done:
		}
	}(m.Name())
}

// stopAll 反序关闭所有模块，聚合各模块的关闭错误
//
// 单个模块关闭出错或超时不打断序列 - 继续关下一个（尤其是排在最后的 audit
// 必须有机会收尾），但错误会被收集并 join 返回，供上层反映到退出码
func (k *Kernel) stopAll(started []Module) error {
	var errs []error
	for i := len(started) - 1; i >= 0; i-- {
		if err := k.stopModule(started[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// stopModule 关闭单个模块，并强制施加时间上限，返回关闭错误（含超时）
//
// Stop 在独立 goroutine 里跑，本函数只等它 stopTimeout 这么久。超时即放弃等待、
// 返回，让调用方继续关下一个模块 - 那个卡住的 goroutine 会泄漏，但相比让整条
// 关闭序列（含最底层的 audit）永久卡死，泄漏一个 goroutine 是明显更小的代价：
// 进程随后整体退出，泄漏的 goroutine 随之消失，安全性由 systemd 重启与 MCU
// 心跳刹停兜底
//
// 用独立于 Run 的 ctx：触发关闭的信号往往已经让根 ctx 取消，沿用它会让每个
// 模块的 Stop 一进来就看到一个已取消的 context，收尾逻辑直接被跳过
func (k *Kernel) stopModule(m Module) error {
	k.log.Info("stopping module", "module", m.Name())

	ctx, cancel := context.WithTimeout(context.Background(), k.stopTimeout)
	defer cancel()

	// 容量 1：即便本函数已经超时返回、不再接收，Stop goroutine 结束时的写入
	// 也不会阻塞泄漏在这条通道上
	done := make(chan error, 1)
	go func() { done <- m.Stop(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			// 立即记录，让运维在停机时就看到；同时返回，让退出码也能反映
			k.log.Error("module failed to stop", "module", m.Name(), "err", err)
			return fmt.Errorf("stop %s: %w", m.Name(), err)
		}
		return nil
	case <-ctx.Done():
		k.log.Error("module stop timed out; abandoning and continuing shutdown",
			"module", m.Name(), "timeout", k.stopTimeout)
		return fmt.Errorf("stop %s: timed out after %s", m.Name(), k.stopTimeout)
	}
}
