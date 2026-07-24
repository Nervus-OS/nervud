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

type fakeModule struct {
	name     string
	rec      *recorder
	startErr error
	stopErr  error

	fatal chan error

	stopBlock time.Duration

	ignoreStopCtx bool

	sawDeadline atomic.Bool

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

type fatalModule struct{ *fakeModule }

func (m *fatalModule) Fatal() <-chan error { return m.fatal }

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

	want := []string{
		"start:a", "start:b", "start:c",
		"stop:c", "stop:b", "stop:a",
	}
	if got := rec.snapshot(); !equal(got, want) {
		t.Fatalf("Order = %v\nwant  %v", got, want)
	}
}

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

func TestStopAll_PassesDeadlineToModules(t *testing.T) {
	rec := &recorder{}
	slow := &fakeModule{
		name: "slow", rec: rec,
		stopBlock: 10 * time.Second,
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
		t.Fatalf("shutdown took %v; the timeout did not take effect", elapsed)
	}
	if !slow.sawDeadline.Load() {
		t.Fatal("module Stop did not receive a context with a deadline")
	}
}

func TestStopModule_HardTimeoutOnUncooperativeModule(t *testing.T) {
	rec := &recorder{}
	stuck := &fakeModule{
		name: "stuck", rec: rec,
		stopBlock: 10 * time.Second, ignoreStopCtx: true,
	}
	victim := &fakeModule{name: "victim", rec: rec}

	k := New(discardLog())
	k.stopTimeout = 100 * time.Millisecond
	k.Register(victim)
	k.Register(stuck)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()
	waitForSteps(t, rec, 2)

	start := time.Now()
	cancel()
	<-done
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("shutdown took %v; the hard timeout did not escape the stuck Stop", elapsed)
	}
	if stuck.stopReturned.Load() {
		t.Fatal("stuck.Stop returned, so the test did not exercise a context-ignoring Stop")
	}
	steps := rec.snapshot()
	var sawVictimStop bool
	for _, s := range steps {
		if s == "stop:victim" {
			sawVictimStop = true
		}
	}
	if !sawVictimStop {
		t.Fatalf("a stuck module blocked cleanup of later modules, steps=%v", steps)
	}
}

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
		t.Fatal("Run must return a non-nil error when cleanup fails during normal shutdown")
	}
}

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

func TestRun_ShutdownDuringStartup(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())

	blocker := &startBlockModule{
		fakeModule: &fakeModule{name: "blocker", rec: rec},
		release:    ctx,
	}

	k := New(discardLog())
	k.Register(&fakeModule{name: "a", rec: rec})
	k.Register(blocker)
	k.Register(&fakeModule{name: "never", rec: rec})

	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	waitForSteps(t, rec, 2)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("shutdown during startup should return nil, got %v", err)
	}
	steps := rec.snapshot()
	for _, s := range steps {
		if s == "start:never" {
			t.Fatalf("startup continued after shutdown, steps=%v", steps)
		}
	}
	var sawStopA bool
	for _, s := range steps {
		if s == "stop:a" {
			sawStopA = true
		}
	}
	if !sawStopA {
		t.Fatalf("an already started module was not rolled back, steps=%v", steps)
	}
}

func TestRun_FatalDuringStartup(t *testing.T) {
	rec := &recorder{}
	boom := errors.New("early fatal")

	fm := &fatalModule{&fakeModule{name: "faulty", rec: rec, fatal: make(chan error, 1)}}
	fm.fatal <- boom

	slowStart := &startBlockModule{
		fakeModule: &fakeModule{name: "slow", rec: rec},
		delay:      500 * time.Millisecond,
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
			t.Fatal("startup should not continue after a fatal error")
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
