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

type ctrlSpawner struct {
	mu        sync.Mutex
	startN    map[string]int
	stopN     map[string]int
	exit      map[string]chan systemd.ExitInfo
	startErr  error
	startGate chan struct{}
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
	gate := s.startGate
	s.mu.Unlock()
	if gate != nil {
		<-gate
	}
	s.mu.Lock()
	s.startN[spec.Name]++
	err := s.startErr
	s.mu.Unlock()
	s.exitCh(spec.Name)
	return err
}

func (s *ctrlSpawner) stops(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopN[name]
}

func (s *ctrlSpawner) StopUnit(_ context.Context, name string) error {
	s.mu.Lock()
	s.stopN[name]++
	s.mu.Unlock()
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

func (s *ctrlSpawner) crash(name string) {
	s.exitCh(name) <- systemd.ExitInfo{ActiveState: "failed", Result: "exit-code"}
}

func (s *ctrlSpawner) starts(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startN[name]
}

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

func onDemandService(id string, crit pkgregistry.Criticality) pkgregistry.Component {
	return pkgregistry.Component{
		ID: id, Type: pkgregistry.ComponentService, Runtime: pkgregistry.RuntimeNative,
		Entry: "bin", LaunchMode: pkgregistry.LaunchOnDemand, Criticality: crit,
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
	sp.crash(unit)
	waitFor(t, time.Second, func() bool { return sp.starts(unit) >= 2 })
}

func TestCircuitBreak_VitalEscalatesSafety(t *testing.T) {
	sp := newCtrlSpawner()
	fs := &fakeSafety{}
	pkgs := &fakePkgs{entries: []pkgregistry.Entry{
		makeEntry("nervus.core", 20002, identity.TrustPlatform,
			alwaysOnService("provider", pkgregistry.CriticalityVital)),
	}}
	m := newTestManager(t, sp, pkgs, fs)
	defer func() { _ = m.Stop(context.Background()) }()
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	unit := unitName("nervus.core", "provider")
	for i := 0; i < crashThreshold; i++ {
		waitFor(t, time.Second, func() bool { return sp.starts(unit) >= i+1 })
		sp.crash(unit)
	}
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
	time.Sleep(30 * time.Millisecond)
	if n := sp.starts(unit); n != 1 {
		t.Fatalf("stopped component restarted: starts=%d, want 1", n)
	}
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateStopped
	})
}

func TestStopDuringStarting_StillStopsUnit(t *testing.T) {
	sp := newCtrlSpawner()
	sp.startGate = make(chan struct{})
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

	done := make(chan struct{})
	go func() { _ = m.StopComponent(context.Background(), "com.example.app", "worker"); close(done) }()
	time.Sleep(20 * time.Millisecond)

	close(sp.startGate)
	<-done

	waitFor(t, 2*time.Second, func() bool { return sp.stops(unit) >= 1 })
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateStopped
	})
}

func TestReloadPackage_RestartsFromCurrentRegistry(t *testing.T) {
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

	if err := m.ReloadPackage(context.Background(), "com.example.app"); err != nil {
		t.Fatalf("ReloadPackage: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return sp.starts(unit) == 2 })
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateRunning
	})
}

func TestEnsureStarted_RestartsAfterStop(t *testing.T) {
	sp := newCtrlSpawner()
	pkgs := &fakePkgs{entries: []pkgregistry.Entry{
		makeEntry("com.example.app", 20001, identity.TrustOrdinary,
			onDemandService("worker", pkgregistry.CriticalityOptional)),
	}}
	m := newTestManager(t, sp, pkgs, &fakeSafety{})
	defer func() { _ = m.Stop(context.Background()) }()

	unit := unitName("com.example.app", "worker")

	if err := m.EnsureStarted(context.Background(), "com.example.app", "worker"); err != nil {
		t.Fatalf("first EnsureStarted: %v", err)
	}
	waitFor(t, time.Second, func() bool { return sp.starts(unit) >= 1 })

	if err := m.StopComponent(context.Background(), "com.example.app", "worker"); err != nil {
		t.Fatalf("StopComponent: %v", err)
	}
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateStopped
	})

	if err := m.EnsureStarted(context.Background(), "com.example.app", "worker"); err != nil {
		t.Fatalf("second EnsureStarted after stop: %v", err)
	}
	waitFor(t, time.Second, func() bool { return sp.starts(unit) >= 2 })
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateRunning
	})
}

func TestEnsureStarted_RestartsAfterCircuitBreak(t *testing.T) {
	sp := newCtrlSpawner()
	pkgs := &fakePkgs{entries: []pkgregistry.Entry{
		makeEntry("com.example.app", 20001, identity.TrustOrdinary,
			onDemandService("worker", pkgregistry.CriticalityOptional)),
	}}
	m := newTestManager(t, sp, pkgs, &fakeSafety{})
	defer func() { _ = m.Stop(context.Background()) }()

	unit := unitName("com.example.app", "worker")

	if err := m.EnsureStarted(context.Background(), "com.example.app", "worker"); err != nil {
		t.Fatalf("first EnsureStarted: %v", err)
	}
	for i := 0; i < crashThreshold; i++ {
		waitFor(t, time.Second, func() bool { return sp.starts(unit) >= i+1 })
		sp.crash(unit)
	}
	waitFor(t, time.Second, func() bool {
		inst, ok := m.LookupByUnit(unit)
		return ok && inst.State == StateFailed
	})
	startsBeforeRetry := sp.starts(unit)

	if err := m.EnsureStarted(context.Background(), "com.example.app", "worker"); err != nil {
		t.Fatalf("EnsureStarted after circuit break: %v", err)
	}
	waitFor(t, time.Second, func() bool { return sp.starts(unit) > startsBeforeRetry })
}
