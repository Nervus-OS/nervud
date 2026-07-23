// Package kernel 管理内核模块的有序启动与反序关闭
// 它只依赖 Module 接口，不 import 任何具体模块，以保证依赖单向
// Kernel 只认接口，装配细节留给 main，便于对生命周期做单测
package kernel

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Module 是所有内核模块的统一生命周期契约
//
// # Start 应快速返回：长期运行的循环自行开 goroutine
//
// 循环的退出只听 Stop()，不听 Start(ctx) 的 ctx。若循环也监听信号 ctx，
// 它会与 stopAll 被同一个信号并行唤醒，谁先退出不确定，停机顺序就不再由
// 反序 Stop 唯一决定；模块的收尾逻辑（撤权、刹停确认、审计落盘）可能被截断
//
// Stop 收到的 ctx 带有超时（moduleStopTimeout），实现必须尊重它。
// Kernel 不会强行放弃一个不返回的 Stop —— 那会让下一个模块的 Stop 与它并发
// 执行，破坏反序关闭这个唯一的顺序保证
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

// moduleStopTimeout 是单个模块 Stop 的时间上限
//
// 逐模块计时而不是给整个关闭序列一个总预算：总预算会让排在后面的模块
// （也就是最底层、收尾最要紧的那些）因为前面的模块慢而被剥夺时间
const moduleStopTimeout = 5 * time.Second

type Kernel struct {
	log     *slog.Logger
	modules []Module
}

func New(log *slog.Logger) *Kernel {
	return &Kernel{log: log}
}

// Register 按调用顺序登记模块；启动顺序 = 注册顺序，关闭顺序 = 反序
// 只在 Run 之前调用（装配阶段），运行期不再增删
func (k *Kernel) Register(m Module) {
	k.modules = append(k.modules, m)
}

// Run 依次启动全部模块；任一启动失败则反序关闭已启动的模块并返回错误
// *请注意 启动失败后，不会 stop 启动失败的模块
//
// 全部启动成功后阻塞，直到二者之一发生：
//
//	ctx 取消        —— 计划内停机，反序 Stop 后返回 nil
//	某模块报告致命错误 —— 反序 Stop 后返回该错误，main 据此非零退出
func (k *Kernel) Run(ctx context.Context) error {
	started := make([]Module, 0, len(k.modules))
	for _, m := range k.modules {
		k.log.Info("starting module", "module", m.Name())
		if err := m.Start(ctx); err != nil {
			k.log.Error("module failed to start; rolling back", "module", m.Name(), "err", err)
			k.stopAll(started)
			return fmt.Errorf("start %s: %w", m.Name(), err)
		}
		started = append(started, m)
	}
	k.log.Info("kernel ready", "modules", len(started))

	// watchDone 让监视 goroutine 随 Run 一起退出，避免它们悬在已经没人读的
	// 模块通道上。defer 在两条返回路径上都生效
	watchDone := make(chan struct{})
	defer close(watchDone)
	fatal := k.watchFatal(started, watchDone)

	select {
	case <-ctx.Done():
		k.log.Info("shutdown signal received; shutting down")
		k.stopAll(started)
		return nil

	case f := <-fatal:
		// 不做局部降级：半死的 TCB 比重启更危险。整体关停后让 systemd 重启，
		// 连续失败由 StartLimitAction=reboot 兜底
		k.log.Error("module reported a fatal error; shutting down kernel",
			"module", f.name, "err", f.err)
		k.stopAll(started)
		return fmt.Errorf("module %s failed at runtime: %w", f.name, f.err)
	}
}

type moduleFailure struct {
	name string
	err  error
}

// watchFatal 把各模块的致命错误通道扇入一条通道
//
// 用扇入而不是 reflect.Select：后者为了处理动态数量的 case 要走反射，
// 代价和可读性都不划算，而这里的 goroutine 数量等于模块数、且随 Run 结束回收
//
// 返回的通道有缓冲，容量等于监视者数量：即使 Kernel 已经在走关闭流程、
// 不再读这条通道，写入方也不会阻塞泄漏
func (k *Kernel) watchFatal(started []Module, done <-chan struct{}) <-chan moduleFailure {
	out := make(chan moduleFailure, len(started))
	for _, m := range started {
		fr, ok := m.(FatalReporter)
		if !ok {
			continue
		}
		ch := fr.Fatal()
		if ch == nil {
			continue
		}
		go func(name string, ch <-chan error) {
			select {
			case err, open := <-ch:
				// 通道被关闭（open=false）不代表故障：模块可能只是在收尾时
				// 关掉了它。只有真的收到一个非 nil error 才算致命
				if open && err != nil {
					select {
					case out <- moduleFailure{name: name, err: err}:
					case <-done:
					}
				}
			case <-done:
			}
		}(m.Name(), ch)
	}
	return out
}

// stopAll 反序关闭所有模块，单个模块关闭出错只记录
//
// 用独立于 Run 的 ctx：触发关闭的信号往往已经让根 ctx 取消，沿用它会让每个
// 模块的 Stop 一进来就看到一个已取消的 context，收尾逻辑直接被跳过
func (k *Kernel) stopAll(started []Module) {
	for i := len(started) - 1; i >= 0; i-- {
		m := started[i]
		k.log.Info("stopping module", "module", m.Name())

		ctx, cancel := context.WithTimeout(context.Background(), moduleStopTimeout)
		err := m.Stop(ctx)
		cancel()

		if err != nil {
			// 继续关后面的模块。一个模块收尾失败不该连累其余模块的收尾——
			// 尤其是排在最后的 audit，它要负责把这些错误本身记下来
			k.log.Error("module failed to stop", "module", m.Name(), "err", err)
		}
	}
}
