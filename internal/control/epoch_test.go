package control

import (
	"errors"
	"testing"
	"time"
)

type epochProbe struct {
	m    *Module
	base uint64
}

func (p *epochProbe) reset()        { p.base = p.m.gate.Epoch() }
func (p *epochProbe) delta() uint64 { return p.m.gate.Epoch() - p.base }

func TestEpochLedger(t *testing.T) {
	tests := []struct {
		name string
		want uint64
		run  func(t *testing.T, p *epochProbe)
	}{
		{
			name: "issue a new lease from NONE",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, humanReq(1))
			},
		},
		{
			name: "HUMAN preemption of AI advances once",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, aiReq(1))
				p.reset()
				mustAcquire(t, p.m, humanReq(2))
			},
		},
		{
			name: "explicit release",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				l := mustAcquire(t, p.m, humanReq(1))
				p.reset()
				if err := p.m.Release(l.ID, l.Conn); err != nil {
					t.Fatalf("Release: %v", err)
				}
			},
		},
		{
			name: "connection closed",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, humanReq(1))
				p.reset()
				p.m.RevokeConn(1)
			},
		},
		{
			name: "refreshing the same lease does not advance",
			want: 0,
			run: func(t *testing.T, p *epochProbe) {
				l := mustAcquire(t, p.m, humanReq(1))
				p.reset()
				if _, err := p.m.Renew(l.ID, l.Conn); err != nil {
					t.Fatalf("Renew: %v", err)
				}
			},
		},
		{
			name: "reacquire on the same connection is an idempotent refresh",
			want: 0,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, humanReq(1))
				p.reset()
				mustAcquire(t, p.m, humanReq(1))
			},
		},
		{
			name: "ordinary command validation does not advance",
			want: 0,
			run: func(t *testing.T, p *epochProbe) {
				l := mustAcquire(t, p.m, humanReq(1))
				p.reset()
				for i := 0; i < 10; i++ {
					if _, err := p.m.Check(l.ID, l.Conn); err != nil {
						t.Fatalf("Check: %v", err)
					}
					if err := p.m.Refresh(l.ID, l.Conn); err != nil {
						t.Fatalf("Refresh: %v", err)
					}
				}
			},
		},
		{
			name: "lease expiry",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				req := aiReq(1)
				req.TTL = 50 * time.Millisecond
				l := mustAcquire(t, p.m, req)
				p.reset()
				p.m.onTick(l.Deadline.Add(time.Millisecond))
			},
		},
		{
			name: "deadman expiry",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				l := mustAcquire(t, p.m, humanReq(1))
				p.reset()
				p.m.onTick(l.IssuedAt.Add(400 * time.Millisecond))
			},
		},
		{
			name: "control does not advance again after a Safety trip",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, humanReq(1))
				p.reset()
				p.m.gate.Trip()
				p.m.RevokeAll(p.m.gate.Epoch())
				p.m.onTick(time.Now())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := newTestModule(t)
			p := &epochProbe{m: m}
			p.reset()

			tc.run(t, p)

			if got := p.delta(); got != tc.want {
				t.Fatalf("epoch delta = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestTripInvalidatesLeaseImmediately(t *testing.T) {
	m, g, _ := newTestModule(t)
	l := mustAcquire(t, m, humanReq(1))

	if _, err := m.Check(l.ID, l.Conn); err != nil {
		t.Fatalf("Check before trip: %v", err)
	}

	g.Trip()

	if _, err := m.Check(l.ID, l.Conn); !errors.Is(err, ErrSafetyLatched) {
		t.Fatalf("Check after trip = %v, want ErrSafetyLatched", err)
	}
}

func TestRevokeAllClearsSlotWithoutBump(t *testing.T) {
	m, g, rec := newTestModule(t)
	mustAcquire(t, m, humanReq(1))

	g.Trip()
	ep := g.Epoch()

	m.RevokeAll(ep)
	if got := g.Epoch(); got != ep {
		t.Fatalf("epoch = %d after RevokeAll, want unchanged %d", got, ep)
	}
	if m.cur.Load() != nil {
		t.Fatal("RevokeAll should have cleared the lease slot")
	}

	m.onTick(time.Now())
	if !rec.has(actionRevoked) {
		t.Fatalf("expected a control.%s audit event, got %v", actionRevoked, rec.actions())
	}
}
