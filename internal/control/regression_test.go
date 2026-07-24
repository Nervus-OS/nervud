package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

func TestAcquire_RejectedAfterStop(t *testing.T) {
	m, _, _ := newTestModule(t)

	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	l, err := m.Acquire(humanReq(1))
	if !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("Acquire after Stop = %v, want ErrShuttingDown", err)
	}
	if l != (Lease{}) || m.cur.Load() != nil {
		t.Fatal("no lease may be published after Stop")
	}
	if _, err := m.Check(l.ID, l.Conn); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("Check on rejected acquire = %v, want ErrControlNotHeld", err)
	}
}

func TestMarkFresh_Monotonic(t *testing.T) {
	m, _, _ := newTestModule(t)

	early := m.base.Add(20 * time.Millisecond)
	late := m.base.Add(100 * time.Millisecond)

	m.markFresh(late)
	m.markFresh(early)

	if got := time.Duration(m.fresh.Load()); got != 100*time.Millisecond {
		t.Fatalf("fresh = %s after a stale write, want 100ms (monotonic)", got)
	}
}

func TestRevokeAll_LosslessAcrossRounds(t *testing.T) {
	m, g, rec := newTestModule(t)

	a := mustAcquire(t, m, humanReq(1))
	g.Trip()
	epoch1 := g.Epoch()
	m.RevokeAll(epoch1)

	if !g.RequireRearm() || !g.Rearm() {
		t.Fatal("failed to walk through rearm between rounds")
	}
	b := mustAcquire(t, m, humanReq(2))
	if b.ID == a.ID {
		t.Fatal("second acquire should mint a fresh lease id")
	}
	g.Trip()
	epoch2 := g.Epoch()
	m.RevokeAll(epoch2)

	m.onTick(time.Now())

	revokes := 0
	for _, e := range rec.all() {
		if e.Action == "control."+actionRevoked {
			revokes++
		}
	}
	if revokes != 2 {
		t.Fatalf("recorded %d LeaseRevoked audits across two rounds, want 2 (lossless)", revokes)
	}
}

func TestRevokeAll_NoBumpAndZeroAlloc(t *testing.T) {
	m, g, _ := newTestModule(t)
	mustAcquire(t, m, humanReq(1))
	g.Trip()
	ep := g.Epoch()

	m.RevokeAll(ep)
	if g.Epoch() != ep {
		t.Fatalf("RevokeAll bumped epoch: %d, want unchanged %d", g.Epoch(), ep)
	}
	if m.cur.Load() != nil {
		t.Fatal("RevokeAll should have cleared the slot")
	}

	if n := testing.AllocsPerRun(200, func() { m.RevokeAll(ep) }); n != 0 {
		t.Fatalf("RevokeAll allocated %v objects per run, want 0", n)
	}
}

func TestDropLocked_NoBumpWhenLatched(t *testing.T) {
	m, g, _ := newTestModule(t)
	mustAcquire(t, m, humanReq(1))
	lp := m.cur.Load()

	g.Trip()
	latchedEpoch := g.Epoch()

	m.mu.Lock()
	m.dropLocked(lp, actionRevoked, errSafetyRevoked)
	m.mu.Unlock()

	if g.Epoch() != latchedEpoch {
		t.Fatalf("dropLocked advanced a latched gate: %d, want %d", g.Epoch(), latchedEpoch)
	}
	if g.State() != motiongate.StateSafetyLatched {
		t.Fatalf("state = %v, want still SAFETY_LATCHED", g.State())
	}
}
