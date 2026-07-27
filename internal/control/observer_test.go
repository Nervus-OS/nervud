package control

import (
	"context"
	"sync"
	"testing"
	"time"
)

type leaseEnd struct {
	conn     ConnID
	resource string
	leaseID  ID
}

type recordingLeaseObserver struct {
	mu     sync.Mutex
	events []leaseEnd
}

var _ LeaseObserver = (*recordingLeaseObserver)(nil)

func (o *recordingLeaseObserver) ControlLeaseEnded(conn ConnID, resource string, leaseID ID) {
	o.mu.Lock()
	o.events = append(o.events, leaseEnd{conn: conn, resource: resource, leaseID: leaseID})
	o.mu.Unlock()
}

func (o *recordingLeaseObserver) snapshot() []leaseEnd {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]leaseEnd, len(o.events))
	copy(out, o.events)
	return out
}

func assertSingleLeaseEnd(t *testing.T, observer *recordingLeaseObserver, lease Lease) {
	t.Helper()
	events := observer.snapshot()
	if len(events) != 1 {
		t.Fatalf("lease end notifications = %+v, want exactly one", events)
	}
	if events[0].conn != lease.Conn || events[0].resource != lease.Resource ||
		events[0].leaseID != lease.ID {
		t.Fatalf("lease end notification = %+v, want conn=%d resource=%q lease=%s",
			events[0], lease.Conn, lease.Resource, lease.ID)
	}
}

func observedTestModule(t *testing.T) (*Module, *recordingLeaseObserver) {
	t.Helper()
	m, _, _ := newTestModule(t)
	observer := &recordingLeaseObserver{}
	m.SetLeaseObserver(observer)
	return m, observer
}

func TestLeaseObserver_Release(t *testing.T) {
	m, observer := observedTestModule(t)
	lease := mustAcquire(t, m, humanReq(1))

	if err := m.Release(lease.ID, lease.Conn); err != nil {
		t.Fatalf("Release: %v", err)
	}
	_ = m.Release(lease.ID, lease.Conn)

	assertSingleLeaseEnd(t, observer, lease)
}

func TestLeaseObserver_DeadlineAndDeadmanExpiry(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		at   func(Lease) time.Time
	}{
		{
			name: "deadline",
			req: func() Request {
				req := aiReq(1)
				req.TTL = 50 * time.Millisecond
				return req
			}(),
			at: func(lease Lease) time.Time {
				return lease.Deadline.Add(time.Millisecond)
			},
		},
		{
			name: "deadman",
			req:  humanReq(1),
			at: func(lease Lease) time.Time {
				return lease.IssuedAt.Add(lease.Deadman + time.Millisecond)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m, observer := observedTestModule(t)
			lease := mustAcquire(t, m, test.req)

			m.onTick(test.at(lease))
			m.onTick(test.at(lease))

			assertSingleLeaseEnd(t, observer, lease)
		})
	}
}

func TestLeaseObserver_HumanPreemption(t *testing.T) {
	m, observer := observedTestModule(t)
	old := mustAcquire(t, m, aiReq(1))

	current := mustAcquire(t, m, humanReq(2))
	if current.Conn != 2 || current.Class != ClassHuman {
		t.Fatalf("current lease = %+v, want HUMAN on conn 2", current)
	}

	assertSingleLeaseEnd(t, observer, old)
}

func TestLeaseObserver_ConnectionAndPackageRevocation(t *testing.T) {
	t.Run("connection", func(t *testing.T) {
		m, observer := observedTestModule(t)
		lease := mustAcquire(t, m, humanReq(11))

		m.RevokeConn(lease.Conn)
		m.RevokeConn(lease.Conn)

		assertSingleLeaseEnd(t, observer, lease)
	})

	t.Run("package", func(t *testing.T) {
		m, observer := observedTestModule(t)
		lease := mustAcquire(t, m, humanReq(12))

		if err := m.RevokeByPackage(lease.Owner.PackageID); err != nil {
			t.Fatalf("RevokeByPackage: %v", err)
		}
		if err := m.RevokeByPackage(lease.Owner.PackageID); err != nil {
			t.Fatalf("second RevokeByPackage: %v", err)
		}

		assertSingleLeaseEnd(t, observer, lease)
	})
}

func TestLeaseObserver_Stop(t *testing.T) {
	m, observer := observedTestModule(t)
	lease := mustAcquire(t, m, humanReq(1))

	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}

	assertSingleLeaseEnd(t, observer, lease)
}

func TestLeaseObserver_SafetyRevokeIsDeferredAndUnique(t *testing.T) {
	m, gate, _ := newTestModule(t)
	observer := &recordingLeaseObserver{}
	m.SetLeaseObserver(observer)
	lease := mustAcquire(t, m, humanReq(1))

	gate.Trip()
	m.RevokeAll(gate.Epoch())
	if events := observer.snapshot(); len(events) != 0 {
		t.Fatalf("RevokeAll invoked observer on the Safety path: %+v", events)
	}

	m.drainRevoked()
	m.drainRevoked()

	assertSingleLeaseEnd(t, observer, lease)
}

func TestLeaseObserver_DoesNotChangeRevokeAllRTContract(t *testing.T) {
	m, gate, _ := newTestModule(t)
	m.SetLeaseObserver(&recordingLeaseObserver{})
	lease := Lease{Conn: 1, Resource: ResourceBaseMain}
	slot := m.slot(ResourceBaseMain)

	allocs := testing.AllocsPerRun(200, func() {
		slot.cur.Store(&lease)
		slot.revoked.Store(nil)
		m.revPending.Store(0)
		m.RevokeAll(gate.Epoch())
	})
	if allocs != 0 {
		t.Fatalf("RevokeAll with observer allocated %v objects per run, want 0", allocs)
	}
}

func TestLeaseObserver_SafetyNotificationPrecedesNextLease(t *testing.T) {
	m, gate, _ := newTestModule(t)
	observer := &recordingLeaseObserver{}
	m.SetLeaseObserver(observer)
	old := mustAcquire(t, m, humanReq(1))

	gate.Trip()
	m.RevokeAll(gate.Epoch())
	if !gate.RequireRearm() || !gate.Rearm() {
		t.Fatal("failed to re-arm gate")
	}

	next := mustAcquire(t, m, humanReq(2))
	if next.Conn != 2 {
		t.Fatalf("next lease conn = %d, want 2", next.Conn)
	}
	assertSingleLeaseEnd(t, observer, old)
}

func TestLeaseObserver_RejectedAcquireDoesNotNotify(t *testing.T) {
	m, gate, _ := newTestModule(t)
	observer := &recordingLeaseObserver{}
	m.SetLeaseObserver(observer)

	gate.Trip()
	if _, err := m.Acquire(humanReq(1)); err == nil {
		t.Fatal("Acquire while Safety is latched succeeded")
	}
	if events := observer.snapshot(); len(events) != 0 {
		t.Fatalf("rejected Acquire emitted terminal notification: %+v", events)
	}
}
