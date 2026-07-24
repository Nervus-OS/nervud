package safety

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

func moduleWith(sp *fakeSpawner, c Contract) *Module {
	return New(sp, motiongate.New(), &collectRecorder{}, nil, c, NopPath(), NopReports(), nil)
}

func TestStart_SpawnsTwoLanesThenStops(t *testing.T) {
	sp := &fakeSpawner{}
	m := moduleWith(sp, DefaultContract())

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	names := sp.laneNames()
	if len(names) != 2 || names[0] != "safety-stop" || names[1] != "safety-supervisor" {
		t.Fatalf("lanes = %v, want [safety-stop safety-supervisor]", names)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestStart_InvalidContractFailsFast(t *testing.T) {
	m := moduleWith(&fakeSpawner{}, Contract{})
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("Start with invalid contract should fail")
	}
}

func TestStart_LaneSpawnErrorFailsFast(t *testing.T) {
	sp := &fakeSpawner{failOn: map[string]error{"safety-supervisor": errors.New("boom")}}
	m := moduleWith(sp, DefaultContract())
	err := m.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Start err = %v, want to wrap 'boom'", err)
	}
}

func TestLane_UnexpectedExitReportsFatal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sp := &fakeSpawner{run: true, ctx: ctx}
	m := moduleWith(sp, DefaultContract())
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	cancel()

	select {
	case err := <-m.Fatal():
		if err == nil {
			t.Fatal("Fatal reported nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a Fatal report after unexpected lane exit")
	}
	_ = m.Stop(context.Background())
}

func TestStop_CleanExitNoFatal(t *testing.T) {
	sp := &fakeSpawner{run: true, ctx: context.Background()}
	m := moduleWith(sp, DefaultContract())
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-m.Fatal():
		t.Fatalf("unexpected Fatal on clean stop: %v", err)
	default:
	}
}

func TestAuditDrain_RecordsHaltDelivered(t *testing.T) {
	rec := &collectRecorder{}
	m := New(&fakeSpawner{}, motiongate.New(), rec, nil,
		DefaultContract(), NopPath(), NopReports(), nil)

	m.deliverHalt()
	m.drainAll()

	found := false
	for _, e := range rec.all() {
		if e.Action == "safety.halt_delivered" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a safety.halt_delivered audit event, got %+v", rec.all())
	}
}

func TestObserverAndController(t *testing.T) {
	m := newTestModule()

	if snap := m.SafetySnapshot(); snap.State != motiongate.StateNormal || snap.Epoch != 1 {
		t.Fatalf("initial snapshot = %+v, want NORMAL/epoch 1", snap)
	}

	m.RequestStop(ReasonOperatorEStop)

	snap := m.SafetySnapshot()
	if snap.State != motiongate.StateSafetyLatched || snap.Epoch != 2 {
		t.Fatalf("after RequestStop snapshot = %+v, want SAFETY_LATCHED/epoch 2", snap)
	}
}

func TestRearmRequiresSettledStopProgress(t *testing.T) {
	tests := []struct {
		phase StopPhase
		allow bool
	}{
		{phase: PhaseUnspecified},
		{phase: PhaseRequested},
		{phase: PhaseSent},
		{phase: PhaseProviderAccepted},
		{phase: PhaseMCUAcked},
		{phase: PhaseOutputDisabled, allow: true},
		{phase: PhaseStandstillConfirmed, allow: true},
		{phase: PhaseDeliveryFault, allow: true},
		{phase: PhaseStandstillTimeout, allow: true},
	}

	for _, tc := range tests {
		t.Run(tc.phase.String(), func(t *testing.T) {
			rec := &collectRecorder{}
			m := New(&fakeSpawner{}, motiongate.New(), rec, nil,
				DefaultContract(), NopPath(), NopReports(), nil)

			m.Trip(ReasonOperatorEStop)
			if !m.gate.RequireRearm() {
				t.Fatal("RequireRearm should succeed from SAFETY_LATCHED")
			}
			m.phase.Store(packPhase(tc.phase, m.gate.Epoch()))

			if got := m.Rearm(); got != tc.allow {
				t.Fatalf("Rearm() = %v, want %v (phase %s)", got, tc.allow, tc.phase)
			}

			wantState := motiongate.StateRearmRequired
			if tc.allow {
				wantState = motiongate.StateNormal
			}
			if got := m.gate.State(); got != wantState {
				t.Fatalf("state = %v, want %v", got, wantState)
			}

			if !tc.allow {
				found := false
				for _, e := range rec.all() {
					if e.Action == "safety.rearm_rejected" {
						found = true
					}
				}
				if !found {
					t.Fatal("a refused re-arm must leave an audit record")
				}
			}
		})
	}
}
