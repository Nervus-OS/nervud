package safety

import (
	"testing"

	"github.com/nervus-os/nervud/internal/motiongate"
)

func TestRearm_RejectsPhaseFromPriorRound(t *testing.T) {
	rec := &collectRecorder{}
	m := New(&fakeSpawner{}, motiongate.New(), rec, nil,
		DefaultContract(), NopPath(), NopReports(), nil)

	m.Trip(ReasonOperatorEStop)
	round1 := m.gate.Epoch()
	m.phase.Store(packPhase(PhaseOutputDisabled, round1))
	if !m.gate.RequireRearm() {
		t.Fatal("round1 RequireRearm should succeed")
	}
	if !m.Rearm() {
		t.Fatal("round1 Rearm should succeed (phase settled and bound to this round)")
	}
	if m.gate.State() != motiongate.StateNormal {
		t.Fatalf("after round1 rearm state = %v, want NORMAL", m.gate.State())
	}

	m.Trip(ReasonExternalTrip)
	round2 := m.gate.Epoch()
	if round2 == round1 {
		t.Fatal("second trip must advance the epoch")
	}
	if !m.gate.RequireRearm() {
		t.Fatal("round2 RequireRearm should succeed")
	}

	if m.Rearm() {
		t.Fatal("round2 Rearm must be REJECTED: the settled phase belongs to the prior round")
	}
	if m.gate.State() != motiongate.StateRearmRequired {
		t.Fatalf("new latch was defeated: state = %v, want REARM_REQUIRED", m.gate.State())
	}
	if !hasAction(rec, "safety.rearm_rejected") {
		t.Fatal("a rejected re-arm must leave an audit record")
	}
}

func TestRearm_StateErrorIsAudited(t *testing.T) {
	rec := &collectRecorder{}
	m := New(&fakeSpawner{}, motiongate.New(), rec, nil,
		DefaultContract(), NopPath(), NopReports(), nil)

	m.Trip(ReasonOperatorEStop)
	m.phase.Store(packPhase(PhaseOutputDisabled, m.gate.Epoch()))

	if m.Rearm() {
		t.Fatal("Rearm from SAFETY_LATCHED (not REARM_REQUIRED) must fail")
	}
	if !hasAction(rec, "safety.rearm_rejected") {
		t.Fatal("a state-error re-arm rejection must still be audited")
	}
}

func TestSafetySnapshot_DropsStalePhase(t *testing.T) {
	m := newTestModule()

	m.Trip(ReasonOperatorEStop)
	cur := m.gate.Epoch()
	m.phase.Store(packPhase(PhaseOutputDisabled, cur-1))

	snap := m.SafetySnapshot()
	if snap.Epoch != cur {
		t.Fatalf("snapshot epoch = %d, want %d", snap.Epoch, cur)
	}
	if snap.StopPhase != PhaseUnspecified {
		t.Fatalf("stale phase leaked into snapshot: got %v, want UNSPECIFIED", snap.StopPhase)
	}

	m.phase.Store(packPhase(PhaseOutputDisabled, cur))
	if snap := m.SafetySnapshot(); snap.StopPhase != PhaseOutputDisabled {
		t.Fatalf("current-round phase = %v, want OUTPUT_DISABLED", snap.StopPhase)
	}
}

func hasAction(rec *collectRecorder, action string) bool {
	for _, e := range rec.all() {
		if e.Action == action {
			return true
		}
	}
	return false
}
