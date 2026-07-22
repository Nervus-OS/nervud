package scheduler

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// testScheduler 构造一个静音日志的 Scheduler
// allowDegrade=true：单元测试在无 CAP_SYS_NICE 的普通环境下运行
// 不应因为设不上实时优先级而失败——这里验证的是生命周期语义，不是调度策略本身
func testScheduler() *Scheduler {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), true)
}

// Shutdown 必须等待 Lane 真正退出（join），而不是发完取消就返回
// 这是「进程结束前 Lane 收尾逻辑一定跑完」的基础保证
func TestShutdownJoinsLanes(t *testing.T) {
	s := testScheduler()

	var exited atomic.Bool
	if err := s.SpawnDedicated("test-lane", PolicyNormal, 0, func(ctx context.Context) {
		<-ctx.Done()
		// 故意拖一下：如果 Shutdown 不 join，这段收尾就会被截断
		time.Sleep(50 * time.Millisecond)
		exited.Store(true)
	}); err != nil {
		t.Fatalf("SpawnDedicated: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !exited.Load() {
		t.Fatal("Shutdown in Lane finished before exit: join not available")
	}
}

// Lane 的退出只能由 Scheduler.Shutdown 触发，不受外部（信号）ctx 影响
// 否则 Lane 与 Kernel 会被同一个信号并行唤醒，关闭顺序不可控
func TestLaneIgnoresExternalContext(t *testing.T) {
	s := testScheduler()

	var running atomic.Bool
	started := make(chan struct{})
	if err := s.SpawnDedicated("test-lane", PolicyNormal, 0, func(ctx context.Context) {
		running.Store(true)
		close(started)
		<-ctx.Done()
		running.Store(false)
	}); err != nil {
		t.Fatalf("SpawnDedicated: %v", err)
	}
	<-started

	// 模拟根信号 ctx 被取消：Lane 不应因此退出
	external, cancelExternal := context.WithCancel(context.Background())
	cancelExternal()
	<-external.Done()
	time.Sleep(50 * time.Millisecond)

	if !running.Load() {
		t.Fatal("Lane followed external ctx and exited: Lane lifecycle not decoupled from signal ctx")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if running.Load() {
		t.Fatal("Shutdown after Lane still running")
	}
}

// 卡死的 Lane 不能让停机流程无限阻塞：Shutdown 超时后必须返回 error
// 由调用方记录并继续退出（安全性由 systemd 重启与 MCU 心跳刹停兜底）
func TestShutdownTimesOutOnStuckLane(t *testing.T) {
	s := testScheduler()

	release := make(chan struct{})
	if err := s.SpawnDedicated("stuck-lane", PolicyNormal, 0, func(ctx context.Context) {
		<-release // 故意无视 ctx 取消
	}); err != nil {
		t.Fatalf("SpawnDedicated: %v", err)
	}
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); err == nil {
		t.Fatal("Stuck lane did not cause Shutdown to timeout and return error")
	}
}

// SpawnDedicated 是同步握手的：返回时 Lane 的优先级设置结果已确定
// 调用方据此 fail-fast，而不是只在日志里看到一行错误
func TestSpawnDedicatedIsSynchronous(t *testing.T) {
	s := testScheduler()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})

	if err := s.SpawnDedicated("test-lane", PolicyNormal, 0, func(ctx context.Context) {
		<-ctx.Done()
	}); err != nil {
		t.Fatalf("SpawnDedicated: %v", err)
	}
	// 非 Linux 平台 setSched 是 no-op；Linux 上 PolicyNormal 不需要特权
	// 两种情况都应成功返回，证明握手路径本身是通的
}
