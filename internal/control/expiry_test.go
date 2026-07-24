package control

import (
	"errors"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

func TestExpiryReasons(t *testing.T) {
	tests := []struct {
		name       string
		req        Request
		at         func(l Lease) time.Time
		wantAction string
	}{
		{
			name:       "deadline expiry",
			req:        func() Request { r := aiReq(1); r.TTL = 50 * time.Millisecond; return r }(),
			at:         func(l Lease) time.Time { return l.Deadline.Add(time.Millisecond) },
			wantAction: actionExpired,
		},
		{
			name:       "deadman expiry",
			req:        humanReq(1),
			at:         func(l Lease) time.Time { return l.IssuedAt.Add(400 * time.Millisecond) },
			wantAction: actionDeadmanExpired,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, rec := newTestModule(t)
			l := mustAcquire(t, m, tc.req)

			m.onTick(tc.at(l))

			if m.cur.Load() != nil {
				t.Fatal("expired lease should have been collected by the lane")
			}
			if !rec.has(tc.wantAction) {
				t.Fatalf("expected control.%s, got %v", tc.wantAction, rec.actions())
			}
			if _, err := m.Check(l.ID, l.Conn); !errors.Is(err, ErrControlNotHeld) {
				t.Fatalf("Check after expiry = %v, want ErrControlNotHeld", err)
			}
		})
	}
}

func TestRefreshKeepsDeadmanAlive(t *testing.T) {
	m, _, _ := newTestModule(t)
	l := mustAcquire(t, m, humanReq(1))

	for i := 1; i <= 9; i++ {
		at := l.IssuedAt.Add(time.Duration(i) * 100 * time.Millisecond)
		m.markFresh(at)
		m.onTick(at)
		if m.cur.Load() == nil {
			t.Fatalf("lease dropped at %dms despite fresh input", i*100)
		}
	}

	m.onTick(l.IssuedAt.Add(1300 * time.Millisecond))
	if m.cur.Load() != nil {
		t.Fatal("lease survived a deadman window with no fresh input")
	}
}

func TestLaneIgnoresSafetyOwnedBoundaries(t *testing.T) {
	m, g, _ := newTestModule(t)
	mustAcquire(t, m, humanReq(1))

	g.Trip()
	epochAfterTrip := g.Epoch()

	m.onTick(time.Now().Add(time.Hour))

	if g.Epoch() != epochAfterTrip {
		t.Fatalf("lane bumped epoch on a safety-owned boundary: %d -> %d", epochAfterTrip, g.Epoch())
	}
	if m.cur.Load() == nil {
		t.Fatal("lane collected a lease that belongs to safety's revoke path")
	}
}

func TestControlSnapshot(t *testing.T) {
	m, g, _ := newTestModule(t)

	if s := m.ControlSnapshot(); s.Source != SourceNone || s.Held {
		t.Fatalf("fresh module = %+v, want NONE", s)
	}

	l := mustAcquire(t, m, aiReq(1))
	s := m.ControlSnapshot()
	if s.Source != SourceAI || !s.Held || s.Lease.ID != l.ID {
		t.Fatalf("after AI acquire = %+v, want AI", s)
	}

	mustAcquire(t, m, humanReq(2))
	if s := m.ControlSnapshot(); s.Source != SourceHuman {
		t.Fatalf("after HUMAN preempt = %+v, want HUMAN", s)
	}

	g.Trip()
	s = m.ControlSnapshot()
	if s.Source != SourceSafety {
		t.Fatalf("after trip = %+v, want SAFETY", s)
	}
	if s.State != motiongate.StateSafetyLatched {
		t.Fatalf("snapshot state = %v, want SAFETY_LATCHED", s.State)
	}
}
