package safety

import (
	"testing"

	"github.com/nervus-os/nervud/internal/motiongate"
)

// TestRearm_RejectsPhaseFromPriorRound 复现并锁住 [P1]：新一轮 Safety 不得被上一轮
// 残留的 StopPhase 直接 re-arm。
//
// 序列：上一轮 OUTPUT_DISABLED → Rearm 回 NORMAL → 新 Trip → RequireRearm → Rearm。
// 最后这次 Rearm 读到的相位属于【上一轮】的 epoch；若不绑定 epoch，它会被当成本轮已
// 落定的凭据，把新 latch 解回 NORMAL。绑定后必须拒绝，新 latch 保持。
func TestRearm_RejectsPhaseFromPriorRound(t *testing.T) {
	rec := &collectRecorder{}
	m := New(&fakeSpawner{}, motiongate.New(), rec, nil,
		DefaultContract(), NopPath(), NopReports(), nil)

	// 第一轮：锁存 → 相位落定到 OUTPUT_DISABLED（绑定本轮 epoch）→ 明确 re-arm。
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

	// 第二轮：新 Trip。此刻 m.phase 仍是上一轮的 (OUTPUT_DISABLED @ round1)——Supervisor
	// 还没跑 beginHalt 去重置它。RequireRearm 抢先到位，然后尝试 Rearm。
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

// TestRearm_StateErrorIsAudited 锁住 [P2]：相位已落定且绑定本轮，但 gate.Rearm() 因
// 状态错误（非 REARM_REQUIRED）返回 false 时，也必须留审计。
func TestRearm_StateErrorIsAudited(t *testing.T) {
	rec := &collectRecorder{}
	m := New(&fakeSpawner{}, motiongate.New(), rec, nil,
		DefaultContract(), NopPath(), NopReports(), nil)

	// 锁存并把相位落定到当前轮，但【不】走 RequireRearm——gate 停在 SAFETY_LATCHED。
	m.Trip(ReasonOperatorEStop)
	m.phase.Store(packPhase(PhaseOutputDisabled, m.gate.Epoch()))

	if m.Rearm() {
		t.Fatal("Rearm from SAFETY_LATCHED (not REARM_REQUIRED) must fail")
	}
	if !hasAction(rec, "safety.rearm_rejected") {
		t.Fatal("a state-error re-arm rejection must still be audited")
	}
}

// TestSafetySnapshot_DropsStalePhase 锁住观察面一致性：相位属于旧一轮 epoch 时，
// 快照报告 UNSPECIFIED（本轮尚未开始跟踪），保证 (Epoch, StopPhase) 自洽。
func TestSafetySnapshot_DropsStalePhase(t *testing.T) {
	m := newTestModule()

	m.Trip(ReasonOperatorEStop)
	cur := m.gate.Epoch()
	// 手工塞一个属于「上一轮」的相位。
	m.phase.Store(packPhase(PhaseOutputDisabled, cur-1))

	snap := m.SafetySnapshot()
	if snap.Epoch != cur {
		t.Fatalf("snapshot epoch = %d, want %d", snap.Epoch, cur)
	}
	if snap.StopPhase != PhaseUnspecified {
		t.Fatalf("stale phase leaked into snapshot: got %v, want UNSPECIFIED", snap.StopPhase)
	}

	// 绑定到本轮的相位则如实报告。
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
