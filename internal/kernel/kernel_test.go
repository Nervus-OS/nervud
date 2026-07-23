package kernel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// recorder 记录全部模块的启停顺序，供断言「启动 = 注册序，关闭 = 反序」
type recorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, s)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.steps...)
}

// fakeModule 是可配置的测试模块
type fakeModule struct {
	name     string
	rec      *recorder
	startErr error
	stopErr  error

	// fatal 非 nil 时本模块实现 FatalReporter
	fatal chan error

	// stopBlock 非零时 Stop 会阻塞这么久或直到 ctx 取消，用于测关闭超时
	stopBlock time.Duration

	// ignoreStopCtx 为 true 时 Stop 完全无视 ctx，硬睡 stopBlock。
	// 用于模拟卡锁/卡 syscall/卡日志的不合作模块——这类模块正是硬超时要防的
	ignoreStopCtx bool

	// sawDeadline 在 Stop 入口观察到 ctx 带 deadline 时置位。用 atomic 是因为
	// 硬超时下 Kernel 会放弃等待、Stop goroutine 与测试读取并发
	sawDeadline atomic.Bool

	// stopReturned 在 Stop 真正返回时被置位，用于断言硬超时下 Kernel 是
	// 放弃等待继续走（而不是等这个卡死的 Stop）
	stopReturned atomic.Bool
}

func (m *fakeModule) Name() string { return m.name }

func (m *fakeModule) Start(context.Context) error {
	m.rec.add("start:" + m.name)
	return m.startErr
}

func (m *fakeModule) Stop(ctx context.Context) error {
	m.rec.add("stop:" + m.name)
	defer m.stopReturned.Store(true)

	if _, ok := ctx.Deadline(); ok {
		m.sawDeadline.Store(true)
	}

	if m.stopBlock > 0 {
		if m.ignoreStopCtx {
			// 不合作模块：无视 ctx 硬睡。Kernel 必须靠自己的硬超时脱身
			time.Sleep(m.stopBlock)
		} else {
			select {
			case <-time.After(m.stopBlock):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return m.stopErr
}

// fatalModule 额外实现 FatalReporter
type fatalModule struct{ *fakeModule }

func (m *fatalModule) Fatal() <-chan error { return m.fatal }

// startBlockModule 的 Start 会阻塞，用于制造 启动尚未完成 的时间窗：
// release 非 nil 时阻塞到该 ctx 取消；否则阻塞 delay
type startBlockModule struct {
	*fakeModule
	release context.Context
	delay   time.Duration
}

func (m *startBlockModule) Start(ctx context.Context) error {
	m.rec.add("start:" + m.name)
	switch {
	case m.release != nil:
		<-m.release.Done()
	case m.delay > 0:
		time.Sleep(m.delay)
	}
	return m.startErr
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- 启停顺序 -------------------------------------------------------------

func TestRun_StartsInOrderStopsInReverse(t *testing.T) {
	rec := &recorder{}
	k := New(discardLog())
	for _, n := range []string{"a", "b", "c"} {
		k.Register(&fakeModule{name: n, rec: rec})
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	waitForSteps(t, rec, 3)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{
		"start:a", "start:b", "start:c",
		"stop:c", "stop:b", "stop:a",
	}
	if got := rec.snapshot(); !equal(got, want) {
		t.Fatalf("Order = %v\nwant  %v", got, want)
	}
}

// 启动失败必须反序关闭【已启动】的模块，且不 Stop 失败的那个
func TestRun_StartFailureRollsBack(t *testing.T) {
	rec := &recorder{}
	k := New(discardLog())
	k.Register(&fakeModule{name: "a", rec: rec})
	k.Register(&fakeModule{name: "b", rec: rec, startErr: errors.New("boom")})
	k.Register(&fakeModule{name: "c", rec: rec})

	err := k.Run(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	want := []string{"start:a", "start:b", "stop:a"}
	if got := rec.snapshot(); !equal(got, want) {
		t.Fatalf("Order = %v\nwant  %v", got, want)
	}
}

// --- 致命错误上报 ---------------------------------------------------------

// 这是本次接口修改的核心：模块后台循环失效时，Kernel 必须整体关停并让
// Run 返回错误，从而使 main 非零退出、systemd 重启
func TestRun_FatalErrorShutsDownKernel(t *testing.T) {
	rec := &recorder{}
	k := New(discardLog())

	k.Register(&fakeModule{name: "a", rec: rec})
	fm := &fatalModule{&fakeModule{name: "b", rec: rec, fatal: make(chan error, 1)}}
	k.Register(fm)
	k.Register(&fakeModule{name: "c", rec: rec})

	done := make(chan error, 1)
	go func() { done <- k.Run(context.Background()) }()

	waitForSteps(t, rec, 3)

	boom := errors.New("accept loop aborted")
	fm.fatal <- boom

	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Fatalf("Run err = %v, want wrapping %v", err, boom)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run, did not return due to a fatal error")
	}

	// 关闭仍必须是反序的
	want := []string{
		"start:a", "start:b", "start:c",
		"stop:c", "stop:b", "stop:a",
	}
	if got := rec.snapshot(); !equal(got, want) {
		t.Fatalf("Order = %v\nwant  %v", got, want)
	}
}

// 通道被关闭不等于故障：模块收尾时关掉自己的通道是正常行为，
// 不能被误判成致命错误而触发一次假的内核关停
func TestRun_ClosedFatalChannelIsNotAFailure(t *testing.T) {
	rec := &recorder{}
	k := New(discardLog())
	fm := &fatalModule{&fakeModule{name: "a", rec: rec, fatal: make(chan error)}}
	k.Register(fm)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	waitForSteps(t, rec, 1)
	close(fm.fatal)

	select {
	case err := <-done:
		t.Fatalf("Closing the channel should not have triggered a shutdown, yet `Run` returned %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// 不实现 FatalReporter 的模块必须照常工作（可选接口，不能变成强制）
func TestRun_ModuleWithoutFatalReporter(t *testing.T) {
	rec := &recorder{}
	k := New(discardLog())
	k.Register(&fakeModule{name: "plain", rec: rec})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	waitForSteps(t, rec, 1)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// Fatal() 返回 nil 通道时不能死等，也不能 panic
func TestRun_NilFatalChannel(t *testing.T) {
	rec := &recorder{}
	k := New(discardLog())
	k.Register(&fatalModule{&fakeModule{name: "a", rec: rec, fatal: nil}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	waitForSteps(t, rec, 1)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// --- 关闭超时 -------------------------------------------------------------

// 合作模块：Stop 收到的 ctx 必须带超时，模块监听它就能被及时唤醒
func TestStopAll_PassesDeadlineToModules(t *testing.T) {
	rec := &recorder{}
	slow := &fakeModule{
		name: "slow", rec: rec,
		stopBlock: 10 * time.Second, // 远长于 stopTimeout
	}
	k := New(discardLog())
	k.stopTimeout = 100 * time.Millisecond
	k.Register(slow)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()
	waitForSteps(t, rec, 1)

	start := time.Now()
	cancel()
	<-done
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("关闭耗时 %v，超时没有生效", elapsed)
	}
	if !slow.sawDeadline.Load() {
		t.Fatal("模块的 Stop 没有收到带超时的 ctx")
	}
}

// 不合作模块：Stop 完全无视 ctx（卡锁/卡 syscall/卡日志）。这是本次修复的核心
// ——Kernel 必须靠自己的硬超时脱身，不能被一个不返回的 Stop 永久卡死，且必须
// 继续关闭后续（反序更底层）的模块
func TestStopModule_HardTimeoutOnUncooperativeModule(t *testing.T) {
	rec := &recorder{}
	stuck := &fakeModule{
		name: "stuck", rec: rec,
		stopBlock: 10 * time.Second, ignoreStopCtx: true,
	}
	// 反序里 stuck 排在 victim 之前被关：只有 stuck 的硬超时生效，victim 才轮得到
	victim := &fakeModule{name: "victim", rec: rec}

	k := New(discardLog())
	k.stopTimeout = 100 * time.Millisecond
	k.Register(victim) // 先注册 -> 后关闭
	k.Register(stuck)  // 后注册 -> 先关闭

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()
	waitForSteps(t, rec, 2)

	start := time.Now()
	cancel()
	<-done
	elapsed := time.Since(start)

	// 关闭应在 ~stopTimeout 内完成，而不是等满 stuck 那 10 秒
	if elapsed > 3*time.Second {
		t.Fatalf("关闭耗时 %v，硬超时没有生效（被卡死的 Stop 拖住了）", elapsed)
	}
	// 卡死的 Stop 被放弃时其实还没返回——正是它没返回，才需要硬超时
	if stuck.stopReturned.Load() {
		t.Fatal("stuck.Stop 竟然返回了，用例没有覆盖到 无视 ctx 的场景")
	}
	// 关键：stuck 卡住后，victim 仍然被关闭了
	steps := rec.snapshot()
	var sawVictimStop bool
	for _, s := range steps {
		if s == "stop:victim" {
			sawVictimStop = true
		}
	}
	if !sawVictimStop {
		t.Fatalf("卡死的模块阻断了后续模块的收尾，steps=%v", steps)
	}
}

// 正常信号停机，但某模块 Stop 失败：Run 必须返回错误让 systemd 看见。
// 否则撤权/刹停确认/审计落盘失败时进程仍以 0 退出，systemd 完全无从发现
func TestRun_CleanShutdownSurfacesStopError(t *testing.T) {
	rec := &recorder{}
	k := New(discardLog())
	k.Register(&fakeModule{name: "a", rec: rec, stopErr: errors.New("dirty cleanup")})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()
	waitForSteps(t, rec, 1)
	cancel()

	if err := <-done; err == nil {
		t.Fatal("正常停机但收尾失败，Run 必须返回非 nil 错误")
	}
}

// 一个模块 Stop 失败不该连累其余模块的收尾——尤其是排在最后的 audit
func TestStopAll_ContinuesAfterFailure(t *testing.T) {
	rec := &recorder{}
	k := New(discardLog())
	k.Register(&fakeModule{name: "a", rec: rec})
	k.Register(&fakeModule{name: "b", rec: rec, stopErr: errors.New("stop boom")})
	k.Register(&fakeModule{name: "c", rec: rec})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()
	waitForSteps(t, rec, 3)
	cancel()
	<-done

	want := []string{
		"start:a", "start:b", "start:c",
		"stop:c", "stop:b", "stop:a",
	}
	if got := rec.snapshot(); !equal(got, want) {
		t.Fatalf("Order = %v\nwant  %v", got, want)
	}
}

// --- 启动期响应停机来源 ---------------------------------------------------

// 启动过程中收到 SIGTERM（ctx 取消）：Kernel 必须当场停止启动并回滚已启动的，
// 而不是把剩下的模块也启动完再理会。用一个 Start 里阻塞到 ctx 取消的模块把
// 启动卡在中途，制造这个时间窗
func TestRun_ShutdownDuringStartup(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())

	blocker := &startBlockModule{
		fakeModule: &fakeModule{name: "blocker", rec: rec},
		release:    ctx, // Start 阻塞到 ctx 取消
	}

	k := New(discardLog())
	k.Register(&fakeModule{name: "a", rec: rec})
	k.Register(blocker)
	k.Register(&fakeModule{name: "never", rec: rec}) // 不该被启动

	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	// 等 a 启动、blocker 进入 Start 阻塞
	waitForSteps(t, rec, 2)
	cancel() // 启动中途下发停机

	if err := <-done; err != nil {
		t.Fatalf("启动期停机应返回 nil，得到 %v", err)
	}
	steps := rec.snapshot()
	for _, s := range steps {
		if s == "start:never" {
			t.Fatalf("停机后不该继续启动后续模块，steps=%v", steps)
		}
	}
	// 已启动的 a 必须被回滚
	var sawStopA bool
	for _, s := range steps {
		if s == "stop:a" {
			sawStopA = true
		}
	}
	if !sawStopA {
		t.Fatalf("已启动的模块没有被回滚，steps=%v", steps)
	}
}

// 启动过程中某个已就绪模块立刻 fatal：同样必须当场回滚，不等后续模块启动完
func TestRun_FatalDuringStartup(t *testing.T) {
	rec := &recorder{}
	boom := errors.New("early fatal")

	fm := &fatalModule{&fakeModule{name: "faulty", rec: rec, fatal: make(chan error, 1)}}
	fm.fatal <- boom // 一 Start 完成、watcher 一挂上就能立刻读到

	slowStart := &startBlockModule{
		fakeModule: &fakeModule{name: "slow", rec: rec},
		delay:      500 * time.Millisecond, // 给 fatal 抢先被处理的时间窗
	}

	k := New(discardLog())
	k.Register(fm)
	k.Register(slowStart)
	k.Register(&fakeModule{name: "never", rec: rec})

	err := k.Run(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("Run err = %v, want wrapping %v", err, boom)
	}
	for _, s := range rec.snapshot() {
		if s == "start:never" {
			t.Fatal("启动期 fatal 后不该继续启动后续模块")
		}
	}
}

func waitForSteps(t *testing.T, rec *recorder, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(rec.snapshot()) >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("Timeout waiting for %d steps, got %v", n, rec.snapshot())
}
