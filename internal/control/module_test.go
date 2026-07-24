package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
	"github.com/nervus-os/nervud/internal/safety"
)

var _ safety.LeaseRevoker = (*Module)(nil)

func TestStart_SpawnsControlLane(t *testing.T) {
	sp := &fakeSpawner{}
	m := New(sp, motiongate.New(), &collectRecorder{}, nil, DefaultPolicy())

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if names := sp.laneNames(); len(names) != 1 || names[0] != "control" {
		t.Fatalf("lanes = %v, want [control]", names)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestStart_InvalidPolicyFailsFast(t *testing.T) {
	m := New(&fakeSpawner{}, motiongate.New(), &collectRecorder{}, nil, Policy{})
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("Start with a zero policy should fail")
	}
}

func TestStart_LaneSpawnErrorFailsFast(t *testing.T) {
	sp := &fakeSpawner{failOn: map[string]error{"control": errors.New("boom")}}
	m := New(sp, motiongate.New(), &collectRecorder{}, nil, DefaultPolicy())

	err := m.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Start err = %v, want to wrap 'boom'", err)
	}
}

func TestLane_UnexpectedExitReportsFatal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sp := &fakeSpawner{run: true, ctx: ctx}
	m := New(sp, motiongate.New(), &collectRecorder{}, nil, DefaultPolicy())
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
	m := New(sp, motiongate.New(), &collectRecorder{}, nil, DefaultPolicy())
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

func TestStop_RevokesResidualLease(t *testing.T) {
	m, g, rec := newTestModule(t)
	l := mustAcquire(t, m, humanReq(1))
	before := g.Epoch()

	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if m.cur.Load() != nil {
		t.Fatal("Stop must not leave a lease behind")
	}
	if g.Epoch() != before+1 {
		t.Fatalf("epoch = %d after Stop, want %d", g.Epoch(), before+1)
	}
	if _, err := m.Check(l.ID, l.Conn); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("Check after Stop = %v, want ErrControlNotHeld", err)
	}
	if !rec.has(actionRevoked) {
		t.Fatalf("expected a control.%s audit event, got %v", actionRevoked, rec.actions())
	}
}

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name string
		pol  Policy
		ok   bool
	}{
		{name: "defaults are internally consistent", pol: DefaultPolicy(), ok: true},
		{name: "all-zero policy is invalid", pol: Policy{}},
		{
			name: "deadman required but not configured",
			pol: Policy{
				Human: ClassPolicy{TTL: time.Second, RequireDeadman: true},
				AI:    ClassPolicy{TTL: time.Second},
			},
		},
		{
			name: "deadman longer than TTL is ineffective",
			pol: Policy{
				Human: ClassPolicy{TTL: time.Second, Deadman: 2 * time.Second},
				AI:    ClassPolicy{TTL: time.Second},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.pol.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("Validate = nil, want an error")
			}
		})
	}
}
