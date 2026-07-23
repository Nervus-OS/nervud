package safety

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

func newTestSupervisor(c Contract) (*supervisor, *motiongate.Gate, *auditRing, *atomic.Uint32) {
	g := motiongate.New()
	ring := newAuditRing(256)
	phase := new(atomic.Uint32)
	pending := new(atomic.Uint32)
	phase.Store(uint32(PhaseUnspecified))
	s := &supervisor{gate: g, ring: ring, contract: c, phase: phase, pending: pending}
	return s, g, ring, pending
}

func publishedPhase(s *supervisor) StopPhase { return StopPhase(s.phase.Load()) }

func TestSupervisor_HappyPath(t *testing.T) {
	s, g, ring, pending := newTestSupervisor(contractSupportingStandstill())
	pending.Store(uint32(ReasonOperatorEStop))

	g.Trip() // 锁存，epoch 2
	now := time.Now()
	s.reconcile(now)

	if !s.active || s.haltEpoch != 2 {
		t.Fatalf("after reconcile: active=%v epoch=%d, want true/2", s.active, s.haltEpoch)
	}
	if publishedPhase(s) != PhaseRequested {
		t.Fatalf("phase = %v, want REQUESTED", publishedPhase(s))
	}

	s.onReport(ProviderReport{Kind: ReportHaltAccepted, Epoch: 2}, now)
	if publishedPhase(s) != PhaseProviderAccepted {
		t.Fatalf("phase = %v, want PROVIDER_ACCEPTED", publishedPhase(s))
	}

	s.onReport(ProviderReport{Kind: ReportStopProgress, Epoch: 2, Phase: PhaseOutputDisabled}, now)
	if publishedPhase(s) != PhaseOutputDisabled {
		t.Fatalf("phase = %v, want OUTPUT_DISABLED", publishedPhase(s))
	}

	s.onReport(ProviderReport{Kind: ReportStandstillConfirmed, Epoch: 2}, now)
	if publishedPhase(s) != PhaseStandstillConfirmed {
		t.Fatalf("phase = %v, want STANDSTILL_CONFIRMED", publishedPhase(s))
	}

	kinds := drainKinds(ring)
	if !containsKind(kinds, evTripped) || !containsKind(kinds, evStandstillConfirmed) {
		t.Fatalf("audit kinds = %v, want tripped + standstill_confirmed", kinds)
	}
}

func TestSupervisor_CapWithoutEvidence(t *testing.T) {
	s, g, _, pending := newTestSupervisor(DefaultContract()) // 不支持停稳证据
	pending.Store(uint32(ReasonOperatorEStop))
	g.Trip()
	now := time.Now()
	s.reconcile(now)
	s.onReport(ProviderReport{Kind: ReportStopProgress, Epoch: 2, Phase: PhaseOutputDisabled}, now)
	s.onReport(ProviderReport{Kind: ReportStandstillConfirmed, Epoch: 2}, now)

	if publishedPhase(s) != PhaseOutputDisabled {
		t.Fatalf("phase = %v, want OUTPUT_DISABLED (no evidence)", publishedPhase(s))
	}
}

func TestSupervisor_StaleReportIgnored(t *testing.T) {
	s, g, _, pending := newTestSupervisor(contractSupportingStandstill())
	pending.Store(uint32(ReasonOperatorEStop))
	g.Trip() // epoch 2
	now := time.Now()
	s.reconcile(now)

	s.onReport(ProviderReport{Kind: ReportHaltAccepted, Epoch: 1}, now) // 陈旧 epoch
	if publishedPhase(s) != PhaseRequested {
		t.Fatalf("phase = %v, want REQUESTED (stale report ignored)", publishedPhase(s))
	}
}

func TestSupervisor_TimeoutsEscalateAndLatchHolds(t *testing.T) {
	c := Contract{
		HaltDispatchBudget:    1 * time.Millisecond,
		ProviderAcceptTimeout: 10 * time.Millisecond,
		DeviceStopAckTimeout:  20 * time.Millisecond,
		StandstillTimeout:     30 * time.Millisecond,
		MCUWatchdogTimeout:    5 * time.Millisecond,
	}
	s, g, ring, pending := newTestSupervisor(c)
	pending.Store(uint32(ReasonOperatorEStop))

	g.Trip()
	t0 := time.Now()
	s.reconcile(t0)

	// 一次远超全部预算的 tick：三种升级都应触发。
	s.onTick(t0.Add(100 * time.Millisecond))

	if !s.esc.acceptTimeout || !s.esc.deviceAckTimeout || !s.esc.standstillTimeout {
		t.Fatalf("escalations = %+v, want all true", s.esc)
	}
	if publishedPhase(s) != PhaseStandstillTimeout {
		t.Fatalf("phase = %v, want STANDSTILL_TIMEOUT", publishedPhase(s))
	}
	// Latch 必须保持——超时不清 Safety。
	if st := g.State(); st != motiongate.StateSafetyLatched {
		t.Fatalf("state = %v, latch must hold through standstill timeout", st)
	}

	kinds := drainKinds(ring)
	for _, want := range []eventKind{evProviderAcceptTimeout, evDeviceAckTimeout, evStandstillTimeout} {
		if !containsKind(kinds, want) {
			t.Fatalf("audit kinds = %v, missing %v", kinds, want)
		}
	}
}

func TestSupervisor_TimeoutEscalatesOnce(t *testing.T) {
	c := DefaultContract()
	c.ProviderAcceptTimeout = 10 * time.Millisecond
	c.DeviceStopAckTimeout = 10 * time.Millisecond
	c.StandstillTimeout = 10 * time.Millisecond
	s, g, ring, pending := newTestSupervisor(c)
	pending.Store(uint32(ReasonOperatorEStop))
	g.Trip()
	t0 := time.Now()
	s.reconcile(t0)

	_ = drainKinds(ring) // 清掉 evTripped
	s.onTick(t0.Add(time.Second))
	first := len(drainKinds(ring))
	s.onTick(t0.Add(2 * time.Second)) // 再 tick 不应重复升级
	second := len(drainKinds(ring))
	if second != 0 {
		t.Fatalf("second tick produced %d more events, want 0 (escalate once)", second)
	}
	if first == 0 {
		t.Fatal("first over-budget tick should have escalated")
	}
}

func TestSupervisor_RearmEndsTracking(t *testing.T) {
	s, g, ring, pending := newTestSupervisor(contractSupportingStandstill())
	pending.Store(uint32(ReasonOperatorEStop))
	g.Trip()
	now := time.Now()
	s.reconcile(now)

	g.RequireRearm()
	s.reconcile(now) // REARM_REQUIRED：仍 active
	if !s.active {
		t.Fatal("should stay active in REARM_REQUIRED")
	}

	if !g.Rearm() {
		t.Fatal("Rearm should succeed")
	}
	s.reconcile(now) // NORMAL：结束跟踪
	if s.active {
		t.Fatal("tracking should end after re-arm")
	}
	if publishedPhase(s) != PhaseUnspecified {
		t.Fatalf("phase = %v, want UNSPECIFIED after re-arm", publishedPhase(s))
	}
	if !containsKind(drainKinds(ring), evRearm) {
		t.Fatal("re-arm should be audited")
	}
}

func TestSupervisor_RetripDuringRecovery(t *testing.T) {
	s, g, _, pending := newTestSupervisor(contractSupportingStandstill())
	pending.Store(uint32(ReasonOperatorEStop))

	g.Trip() // epoch 2
	t0 := time.Now()
	s.reconcile(t0)

	g.BeginRecovery() // OEM_RECOVERY
	s.reconcile(t0)   // 不改跟踪
	if s.haltEpoch != 2 {
		t.Fatalf("haltEpoch = %d, want 2 during recovery", s.haltEpoch)
	}

	g.Trip() // 恢复期新触发：重新 latch，epoch 3
	s.reconcile(t0.Add(time.Millisecond))
	if s.haltEpoch != 3 {
		t.Fatalf("haltEpoch = %d, want 3 after re-trip", s.haltEpoch)
	}
	if publishedPhase(s) != PhaseRequested {
		t.Fatalf("phase = %v, want REQUESTED (new halt)", publishedPhase(s))
	}
}
