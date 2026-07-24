package control

import (
	"errors"
	"testing"
	"time"
)

func TestPreemptionMatrix(t *testing.T) {
	tests := []struct {
		name    string
		held    func(ConnID) Request
		want    func(ConnID) Request
		wantErr error
	}{
		{name: "HUMAN preempts AI", held: aiReq, want: humanReq},
		{name: "AI cannot preempt HUMAN", held: humanReq, want: aiReq, wantErr: ErrHeldByHuman},
		{name: "HUMAN cannot preempt HUMAN", held: humanReq, want: humanReq, wantErr: ErrHeldByHuman},
		{name: "AI cannot preempt AI", held: aiReq, want: aiReq, wantErr: ErrHeldByAI},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := newTestModule(t)
			first := mustAcquire(t, m, tc.held(1))

			second, err := m.Acquire(tc.want(2))

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Acquire err = %v, want %v", err, tc.wantErr)
				}
				if _, err := m.Check(first.ID, first.Conn); err != nil {
					t.Fatalf("incumbent lease broke after a denied acquire: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Acquire: %v", err)
			}
			if _, err := m.Check(first.ID, first.Conn); !errors.Is(err, ErrControlNotHeld) {
				t.Fatalf("preempted lease Check = %v, want ErrControlNotHeld", err)
			}
			if _, err := m.Check(second.ID, second.Conn); err != nil {
				t.Fatalf("new lease Check: %v", err)
			}
		})
	}
}

func TestReacquireSameConnIsIdempotent(t *testing.T) {
	m, _, _ := newTestModule(t)
	first := mustAcquire(t, m, humanReq(1))
	again := mustAcquire(t, m, humanReq(1))

	if again.ID != first.ID {
		t.Fatalf("lease id changed on re-acquire: %s -> %s", first.ID, again.ID)
	}
	if again.Deadline.Before(first.Deadline) {
		t.Fatal("re-acquire must not shorten the deadline")
	}
	if _, err := m.Check(first.ID, first.Conn); err != nil {
		t.Fatalf("Check after idempotent re-acquire: %v", err)
	}
}

func TestAcquireRejectsMalformed(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Request)
		wantErr error
	}{
		{
			name:    "zero ConnID",
			mutate:  func(r *Request) { r.Conn = 0 },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "unspecified Class including NONE",
			mutate:  func(r *Request) { r.Class = ClassUnspecified },
			wantErr: ErrInvalidRequest,
		},
		{
			name:    "Resource is not base.main",
			mutate:  func(r *Request) { r.Resource = "arm.left" },
			wantErr: ErrUnknownResource,
		},
		{
			name:    "TTL exceeds Policy limit",
			mutate:  func(r *Request) { r.TTL = time.Hour },
			wantErr: ErrPolicyViolation,
		},
		{
			name:    "deadman exceeds Policy limit",
			mutate:  func(r *Request) { r.Deadman = time.Minute },
			wantErr: ErrPolicyViolation,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, g, rec := newTestModule(t)
			before := g.Epoch()

			req := humanReq(1)
			tc.mutate(&req)

			if _, err := m.Acquire(req); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Acquire err = %v, want %v", err, tc.wantErr)
			}
			if m.cur.Load() != nil {
				t.Fatal("rejected acquire must not publish a lease")
			}
			if g.Epoch() != before {
				t.Fatalf("rejected acquire bumped epoch: %d -> %d", before, g.Epoch())
			}
			if !rec.has(actionDenied) {
				t.Fatalf("expected a control.%s audit event, got %v", actionDenied, rec.actions())
			}
		})
	}
}

func TestShorterThanPolicyIsAccepted(t *testing.T) {
	m, _, _ := newTestModule(t)

	req := humanReq(1)
	req.TTL = 500 * time.Millisecond
	req.Deadman = 100 * time.Millisecond

	l := mustAcquire(t, m, req)
	if l.TTL != 500*time.Millisecond || l.Deadman != 100*time.Millisecond {
		t.Fatalf("lease = (ttl %s, deadman %s), want (500ms, 100ms)", l.TTL, l.Deadman)
	}
}

func TestAcquireDeniedWhileLatched(t *testing.T) {
	m, g, _ := newTestModule(t)
	g.Trip()

	if _, err := m.Acquire(humanReq(1)); !errors.Is(err, ErrSafetyLatched) {
		t.Fatalf("Acquire while latched = %v, want ErrSafetyLatched", err)
	}
	if m.cur.Load() != nil {
		t.Fatal("no lease may be published while the gate is latched")
	}

	if !g.RequireRearm() || !g.Rearm() {
		t.Fatal("gate did not walk through rearm")
	}
	mustAcquire(t, m, humanReq(1))
}

func TestLeaseIsNotTransferable(t *testing.T) {
	m, _, _ := newTestModule(t)
	l := mustAcquire(t, m, humanReq(1))

	if _, err := m.Check(l.ID, ConnID(99)); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("Check with foreign conn = %v, want ErrControlNotHeld", err)
	}
	if err := m.Release(l.ID, ConnID(99)); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("Release with foreign conn = %v, want ErrControlNotHeld", err)
	}
	if _, err := m.Check(l.ID, l.Conn); err != nil {
		t.Fatalf("owner lost its lease to a foreign release: %v", err)
	}
}

func TestLeaseIDsAreUnpredictable(t *testing.T) {
	m, _, _ := newTestModule(t)

	first := mustAcquire(t, m, humanReq(1))
	if err := m.Release(first.ID, first.Conn); err != nil {
		t.Fatalf("Release: %v", err)
	}
	second := mustAcquire(t, m, humanReq(1))

	if first.ID == second.ID {
		t.Fatal("two leases share the same id")
	}
	var zero ID
	if first.ID == zero || second.ID == zero {
		t.Fatal("lease id is all zeroes")
	}
}
