package scheduler

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"log/slog"
)

// New 创建一个 scheduler
//
// allowDegrade 决定是否允许 实时优先级设置失败时 降级为普通优先级继续运行，只打告警
func New(log *slog.Logger, allowDegrade bool) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		log:          log,
		allowDegrade: allowDegrade,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Scheduler 负责创建绑定 OS 线程并设置实时优先级的执行 Lane
// 并持有全部 Lane 的生命周期（取消 + 等待退出）
type Scheduler struct {
	log          *slog.Logger
	allowDegrade bool

	ctx    context.Context    // 所有 lane 的父 ctx
	cancel context.CancelFunc // Shutdown 时触发
	wg     sync.WaitGroup     // 等待全部 lane 真正退出（join）
}

// SpawnDedicated 启动一个专属线程 + 实时优先级的长期运行 goroutine
//
// 流程说明：
//
//	go func {           // 1) 新开一个 goroutine
//	  runtime.LockOSThread   // 2) 把它钉死在一个专属 OS 线程上：
//	                //  此后 Go 调度器不会把别的 goroutine 调度到
//	                //  这个线程，也不会把当前 goroutine 搬到别的线程
//	                //  这是让调度优先级稳定生效的前提
//	                //  注意：这里故意不defer UnlockOSThread - 因为
//	                //  这个线程被赋予了实时优先级，不能再归还给 Go 运行时
//	                //  复用（否则普通 goroutine 会意外继承高优先级）
//	                //  fn 返回后让该线程随 goroutine 一起结束最干净
//	  lane.applySelf      // 3) 对当前(已锁定)线程设置 SCHED_FIFO/RR + 优先级
//	  ready <- err        // 4) 把设置结果同步回报给调用方
//	  fn(ctx)           // 5) 运行实际循环，直到 Shutdown 取消 ctx
//	}(
//
// 本函数是同步握手的：它阻塞到步骤 4)，因此返回时可以确定优先级已经设好
// （或已确定设不上）。这样调用方才可能对Safety Lane 没有实时优先级做出反应
// 而不是只在日志里看到一行错误
//
// panic 策略：lane 内 panic 不 recover。nervud 整体崩溃退出，由 systemd 重启 +
// MCU 心跳刹停兜底。禁止 recover 后继续运行 - 状态不明的 Safety 路径比死掉的更危险
//
// 参数：
//   - name   Lane 名称，用于日志与诊断
//   - policy  调度策略（FIFO/RR/NORMAL）
//   - priority 实时优先级（1..99；NORMAL 时被忽略并置 0）
//   - fn    长期运行的循环，必须在 ctx.Done 时尽快返回
//
// 注意 fn 收到的 ctx 是 Scheduler 自己的 ctx，不是根信号 ctx
func (s *Scheduler) SpawnDedicated(name string, policy Policy, priority int, fn func(context.Context)) error {
	lane := &Lane{name: name, policy: policy, priority: priority}

	// 容量 1：即使调用方因故不再接收，goroutine 也不会卡在这里泄漏
	ready := make(chan error, 1)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// 2) 绑定专属 OS 线程。故意不 UnlockOSThread：见上方大段说明
		runtime.LockOSThread()

		// 3) 应用实时调度策略。Linux 上是真实 syscall；非 Linux 上是 no-op
		err := lane.applySelf()
		ready <- err // 4) 同步回报，调用方据此决定 fail-fast 还是降级

		if err != nil && !s.allowDegrade {
			// 生产语义：设不上实时优先级就不要跑这条 lane，让内核整体退出
			return
		}
		if err != nil {
			s.log.Warn("scheduler: lane degraded to normal priority (dev mode)",
				"lane", name, "policy", policy.String(), "priority", priority, "err", err)
		} else {
			s.log.Info("scheduler: lane ready",
				"lane", name, "policy", policy.String(), "priority", priority)
		}

		// 5) 运行实际循环
		fn(s.ctx)
		s.log.Info("scheduler: lane exited", "lane", name)
	}()

	if err := <-ready; err != nil && !s.allowDegrade {
		return fmt.Errorf("lane %s: Can not set real-time scheduling policy %s/%d (production environment does not allow downgrade;"+
			"check CAP_SYS_NICE, LimitRTPRIO and kernel CONFIG_RT_GROUP_SCHED): %w",
			name, policy.String(), priority, err)
	}
	return nil
}

// Shutdown 取消全部 lane 并等待它们真正退出（join）
//
// 为什么必须显式 join：lane 跑在专属 OS 线程上，如果 main 直接返回，进程立即结束
// lane 的收尾逻辑（撤权、刹停确认、审计落盘）不保证跑完。Go 不会等任何 goroutine
//
// 调用时机固定为Kernel.Run 返回之后，形成确定的关闭序：
//
//	SIGTERM -> Kernel.stopAll（反序停模块）-> Kernel.Run 返回 -> Shutdown（回收 lane）-> main 返回
//
// lane 是最底层基建，因此最后回收；ctx 用于给这一步加上限，超时即放弃等待并返回
// error - 此时进程仍会退出，安全性由 systemd 重启与 MCU 心跳刹停兜底
func (s *Scheduler) Shutdown(ctx context.Context) error {
	s.cancel()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("scheduler: lane not exited within timeout: %w", ctx.Err())
	}
}
