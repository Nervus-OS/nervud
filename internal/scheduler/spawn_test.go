package scheduler

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func testScheduler() *Scheduler {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), true)
}

func TestShutdownJoinsLanes(t *testing.T) {
	s := testScheduler()

	var exited atomic.Bool
	if err := s.SpawnDedicated("test-lane", PolicyNormal, 0, func(ctx context.Context) {
		<-ctx.Done()
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

func TestShutdownTimesOutOnStuckLane(t *testing.T) {
	s := testScheduler()

	release := make(chan struct{})
	if err := s.SpawnDedicated("stuck-lane", PolicyNormal, 0, func(ctx context.Context) {
		<-release
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
}
