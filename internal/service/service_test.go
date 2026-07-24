package service

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/authority/systemd"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// ctrlSpawner 是可控的 authority.UnitManager：起进程记账、WaitUnit 阻塞到测试喂一个
// 退出事件。用真实 *authority.Gate 包着它，好让 service 拿到真实的 ProcessHandle
// （unit 字段不导出，测试无法伪造，只能经真实 Gate 产生）
type ctrlSpawner struct {
	mu       sync.Mutex
	startN   map[string]int
	stopN    map[string]int
	exit     map[string]chan systemd.ExitInfo
	startErr error
}

func newCtrlSpawner() *ctrlSpawner {
	return &ctrlSpawner{
		startN: map[string]int{}, stopN: map[string]int{},
		exit: map[string]chan systemd.ExitInfo{},
	}
}

func (s *ctrlSpawner) exitCh(name string) chan systemd.ExitInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exit[name] == nil {
		s.exit[name] = make(chan systemd.ExitInfo, 16)
	}
	return s.exit[name]
}

func (s *ctrlSpawner) StartTransientUnit(_ context.Context, spec systemd.UnitSpec) error {
	s.mu.Lock()
	s.startN[spec.Name]++
	err := s.startErr
	s.mu.Unlock()
	s.exitCh(spec.Name) // 确保 channel 存在
	return err
}

func (s *ctrlSpawner) StopUnit(_ context.Context, name string) error {
	s.mu.Lock()
	s.stopN[name]++
	s.mu.Unlock()
	// 让阻塞中的 WaitUnit 返回（模拟被停后 unit 变 inactive）
	select {
	case s.exitCh(name) <- systemd.ExitInfo{ActiveState: "inactive"}:
	default:
	}
	return nil
}

func (s *ctrlSpawner) WaitUnit(ctx context.Context, name string) (systemd.ExitInfo, error) {
	select {
	case info := <-s.exitCh(name):
		return info, nil
	case <-ctx.Done():
		return systemd.ExitInfo{}, ctx.Err()
	}
}

// crash 让某个 unit 的下一次 WaitUnit 返回（模拟崩溃）
func (s *ctrlSpawner) crash(name string) {
	s.exitCh(name) <- systemd.ExitInfo{ActiveState: "failed", Result: "exit-code"}
}

func (s *ctrlSpawner) starts(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startN[name]
}

// fakePkgs 是可控的 PackageLookup
type fakePkgs struct{ entries []pkgregistry.Entry }

func (f *fakePkgs) List() []pkgregistry.Entry { return f.entries }
func (f *fakePkgs) Lookup(id string) (pkgregistry.Entry, bool) {
	for _, e := range f.entries {
		if e.Manifest.PackageID == id {
			return e, true
		}
	}
	return pkgregistry.Entry{}, false
}

// fakeSafety 记录 Trip 调用
type fakeSafety struct {
	mu   sync.Mutex
	trip int
}

func (f *fakeSafety) Trip() { f.mu.Lock(); f.trip++; f.mu.Unlock() }
func (f *fakeSafety) trips() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.trip
}

type fakeAud struct {
	mu sync.Mutex
	ev []audit.Event
}

func (f *fakeAud) Record(_ context.Context, e audit.Event) {
	f.mu.Lock()
	f.ev = append(f.ev, e)
	f.mu.Unlock()
}

func testInvariants() *authority.Invariants {
	return authority.DefaultInvariants()
}

func makeEntry(pkg string, uid uint32, trust identity.TrustProfile, comps ...pkgregistry.Component) pkgregistry.Entry {
	return pkgregistry.Entry{
		Manifest:      pkgregistry.Manifest{PackageID: pkg, Version: "1.0.0", Components: comps},
		ActiveVersion: "1.0.0", VersionCode: 100, UID: uid, Trust: trust,
	}
}

func alwaysOnService(id string, crit pkgregistry.Criticality) pkgregistry.Component {
	return pkgregistry.Component{
		ID: id, Type: pkgregistry.ComponentService, Runtime: pkgregistry.RuntimeNative,
		Entry: "bin", LaunchMode: pkgregistry.LaunchAlwaysOn, Criticality: crit,
	}
}

func newTestManager(t *testing.T, sp authority.UnitManager, pkgs PackageLookup, safety SafetyEscalator) *Manager {
	t.Helper()
	rec := &fakeRecorderDiscard{}
	gate, err := authority.New(authority.Config{
		Auditor: rec, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Spawner: sp,
	})
	if err != nil {
		t.Fatalf("authority.New: %v", err)
	}
	aud := &fakeAud{}
	m := New(gate, pkgs, safety, aud, slog.New(slog.NewTextHandler(io.Discard, nil)), testInvariants())
	m.backoffMin = time.Millisecond
	m.backoffMax = 2 * time.Millisecond
	return m
}

type fakeRecorderDiscard struct{}

func (fakeRecorderDiscard) Record(context.Context, audit.Event) {}

// waitFor 轮询 cond 直到成立或超时
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

func TestStart_LaunchesAlwaysOnEnabled(t *testing.T) {
	sp := newCtrlSpawner()
	pkgs := &fakePkgs{entries: []pkgregistry.Entry{
		makeEntry("com.example.app", 20001, identity.TrustOrdinary,
			alwaysOnService("worker", pkgregistry.CriticalityOptional)),
	}}
	m := newTestManager(t, sp, pkgs, &fakeSafety{})
	defer func() { _ = m.Stop(context.Background()) }()

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	unit := unitName("com.example.app", "worker")
	waitFor(t, time.Second, func() bool { return sp.starts(unit) == 1 })

	// LookupByUnit 应能反查到它，状态 Running
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateRunning && inst.ComponentID == "worker" && inst.UID == 20001
	})
}

func TestCrash_RestartsWithBackoff(t *testing.T) {
	sp := newCtrlSpawner()
	pkgs := &fakePkgs{entries: []pkgregistry.Entry{
		makeEntry("com.example.app", 20001, identity.TrustOrdinary,
			alwaysOnService("worker", pkgregistry.CriticalityOptional)),
	}}
	m := newTestManager(t, sp, pkgs, &fakeSafety{})
	defer func() { _ = m.Stop(context.Background()) }()
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	unit := unitName("com.example.app", "worker")
	waitFor(t, time.Second, func() bool { return sp.starts(unit) >= 1 })
	// 崩一次 → 应被重启（start 计数 >= 2）
	sp.crash(unit)
	waitFor(t, time.Second, func() bool { return sp.starts(unit) >= 2 })
}

func TestCircuitBreak_VitalEscalatesSafety(t *testing.T) {
	sp := newCtrlSpawner()
	fs := &fakeSafety{}
	pkgs := &fakePkgs{entries: []pkgregistry.Entry{
		// Platform 信任的 Vital 组件（Ordinary 会被降级，见另一个测试）
		makeEntry("nervus.core", 20002, identity.TrustPlatform,
			alwaysOnService("provider", pkgregistry.CriticalityVital)),
	}}
	m := newTestManager(t, sp, pkgs, fs)
	defer func() { _ = m.Stop(context.Background()) }()
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	unit := unitName("nervus.core", "provider")
	// 连续崩溃直到熔断（阈值 5）。每次崩溃后 supervisor 会重启，需等它重新起来再崩
	for i := 0; i < crashThreshold; i++ {
		waitFor(t, time.Second, func() bool { return sp.starts(unit) >= i+1 })
		sp.crash(unit)
	}
	// 熔断后：Vital → Safety Trip 被调用；组件进 Failed
	waitFor(t, 2*time.Second, func() bool { return fs.trips() >= 1 })
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateFailed
	})
}

func TestEffectiveCriticality_OrdinaryDowngraded(t *testing.T) {
	e := makeEntry("com.third.party", 20003, identity.TrustOrdinary)
	c := alwaysOnService("svc", pkgregistry.CriticalityVital)
	if got := effectiveCriticality(e, c); got != pkgregistry.CriticalityOptional {
		t.Fatalf("Ordinary vital should downgrade to optional, got %q", got)
	}
	// Platform 保留
	e2 := makeEntry("nervus.core", 20004, identity.TrustPlatform)
	if got := effectiveCriticality(e2, c); got != pkgregistry.CriticalityVital {
		t.Fatalf("Platform vital should stay vital, got %q", got)
	}
}

func TestStopComponent_NoRestart(t *testing.T) {
	sp := newCtrlSpawner()
	pkgs := &fakePkgs{entries: []pkgregistry.Entry{
		makeEntry("com.example.app", 20001, identity.TrustOrdinary,
			alwaysOnService("worker", pkgregistry.CriticalityOptional)),
	}}
	m := newTestManager(t, sp, pkgs, &fakeSafety{})
	defer func() { _ = m.Stop(context.Background()) }()
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	unit := unitName("com.example.app", "worker")
	waitFor(t, time.Second, func() bool { return sp.starts(unit) >= 1 })

	if err := m.StopComponent(context.Background(), "com.example.app", "worker"); err != nil {
		t.Fatalf("StopComponent: %v", err)
	}
	// 停止是预期内的，不应重启：等一小会，start 计数应稳定在 1
	time.Sleep(30 * time.Millisecond)
	if n := sp.starts(unit); n != 1 {
		t.Fatalf("stopped component restarted: starts=%d, want 1", n)
	}
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateStopped
	})
}
