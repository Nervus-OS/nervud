package control

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

const (
	resourceArmMain     = "arm.main"
	resourceGripperMain = "gripper.main"
)

func requestForResource(req Request, resource string) Request {
	req.Resource = resource
	return req
}

func TestIndependentResourceSlots(t *testing.T) {
	m, gate, _ := newTestModule(t)
	base := mustAcquire(t, m, humanReq(1))
	arm := mustAcquire(t, m, requestForResource(aiReq(2), resourceArmMain))

	baseEpoch, err := m.Check(base.ID, base.Conn)
	if err != nil {
		t.Fatalf("base lease became invalid after arm acquire: %v", err)
	}
	armEpoch, err := m.Check(arm.ID, arm.Conn)
	if err != nil {
		t.Fatalf("arm lease check: %v", err)
	}
	if baseEpoch != base.Epoch || armEpoch != arm.Epoch || armEpoch != gate.Epoch() || baseEpoch >= armEpoch {
		t.Fatalf("resource epochs = base:%d arm:%d gate:%d, want stable base < arm == gate",
			baseEpoch, armEpoch, gate.Epoch())
	}

	if _, err := m.Acquire(aiReq(3)); !errors.Is(err, ErrHeldByHuman) {
		t.Fatalf("base contention = %v, want ErrHeldByHuman", err)
	}
	if _, err := m.Check(arm.ID, arm.Conn); err != nil {
		t.Fatalf("base contention disturbed arm lease: %v", err)
	}

	humanArm := mustAcquire(t, m, requestForResource(humanReq(4), resourceArmMain))
	if _, err := m.Check(arm.ID, arm.Conn); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("preempted arm lease = %v, want ErrControlNotHeld", err)
	}
	if _, err := m.Check(base.ID, base.Conn); err != nil {
		t.Fatalf("arm preemption disturbed base lease: %v", err)
	}

	before := gate.Epoch()
	again := mustAcquire(t, m, requestForResource(humanReq(4), resourceArmMain))
	if again.ID != humanArm.ID || gate.Epoch() != before {
		t.Fatalf("same-resource reacquire = id %s epoch %d, want id %s epoch %d",
			again.ID, gate.Epoch(), humanArm.ID, before)
	}
	if _, err := m.Check(base.ID, base.Conn); err != nil {
		t.Fatalf("arm renewal disturbed base lease: %v", err)
	}

	if err := m.Release(humanArm.ID, humanArm.Conn); err != nil {
		t.Fatalf("release arm: %v", err)
	}
	if m.current(resourceArmMain) != nil {
		t.Fatal("arm slot still held after release")
	}
	if _, err := m.Check(base.ID, base.Conn); err != nil {
		t.Fatalf("arm release invalidated base lease: %v", err)
	}
}

func TestControlSnapshotForResource(t *testing.T) {
	m, _, _ := newTestModule(t)
	arm := mustAcquire(t, m, requestForResource(aiReq(2), resourceArmMain))

	if base := m.ControlSnapshot(); base.Held || base.Source != SourceNone {
		t.Fatalf("legacy base snapshot = %+v, want NONE", base)
	}
	got := m.ControlSnapshotFor(resourceArmMain)
	if !got.Held || got.Source != SourceAI || got.Lease.ID != arm.ID {
		t.Fatalf("arm snapshot = %+v, want held AI lease %s", got, arm.ID)
	}
}

func TestResourceSlotsHaveIndependentDeadmanFreshness(t *testing.T) {
	policy := Policy{
		Human: ClassPolicy{TTL: time.Hour, Deadman: 300 * time.Millisecond, RequireDeadman: true},
		AI:    ClassPolicy{TTL: time.Hour},
	}
	m := New(&fakeSpawner{}, motiongate.New(), &collectRecorder{}, nil, policy)
	base := mustAcquire(t, m, humanReq(1))
	arm := mustAcquire(t, m, requestForResource(humanReq(2), resourceArmMain))

	tick := arm.IssuedAt.Add(arm.Deadman + time.Millisecond)
	m.markFresh(m.slot(ResourceBaseMain), tick)
	m.onTick(tick)

	if m.current(resourceArmMain) != nil {
		t.Fatal("arm lease survived on base freshness")
	}
	if _, err := m.Check(base.ID, base.Conn); err != nil {
		t.Fatalf("fresh base lease was invalidated with stale arm: %v", err)
	}
}

func TestBulkRevocationVisitsEveryResourceSlot(t *testing.T) {
	t.Run("connection", func(t *testing.T) {
		m, gate, _ := newTestModule(t)
		base := mustAcquire(t, m, humanReq(7))
		arm := mustAcquire(t, m, requestForResource(humanReq(7), resourceArmMain))
		otherReq := requestForResource(aiReq(8), resourceGripperMain)
		other := mustAcquire(t, m, otherReq)
		before := gate.Epoch()

		m.RevokeConn(7)

		if m.current(ResourceBaseMain) != nil || m.current(resourceArmMain) != nil {
			t.Fatal("RevokeConn left a matching resource lease")
		}
		if _, err := m.Check(other.ID, other.Conn); err != nil {
			t.Fatalf("RevokeConn invalidated another connection: %v", err)
		}
		if gate.Epoch() != before+1 {
			t.Fatalf("bulk connection revoke advanced epoch %d -> %d, want once",
				before, gate.Epoch())
		}
		for _, lease := range []Lease{base, arm} {
			if _, err := m.Check(lease.ID, lease.Conn); !errors.Is(err, ErrControlNotHeld) {
				t.Fatalf("revoked lease %s check = %v", lease.Resource, err)
			}
		}
	})

	t.Run("package", func(t *testing.T) {
		m, _, _ := newTestModule(t)
		base := mustAcquire(t, m, humanReq(1))
		mustAcquire(t, m, requestForResource(humanReq(2), resourceArmMain))
		otherReq := requestForResource(aiReq(3), resourceGripperMain)
		otherReq.Owner = testCaller("com.example.other", 20003)
		other := mustAcquire(t, m, otherReq)

		if err := m.RevokeByPackage(base.Owner.PackageID); err != nil {
			t.Fatalf("RevokeByPackage: %v", err)
		}
		if m.current(ResourceBaseMain) != nil || m.current(resourceArmMain) != nil {
			t.Fatal("RevokeByPackage left a matching resource lease")
		}
		if _, err := m.Check(other.ID, other.Conn); err != nil {
			t.Fatalf("package revoke invalidated another package: %v", err)
		}
	})

	t.Run("safety", func(t *testing.T) {
		m, gate, _ := newTestModule(t)
		observer := &recordingLeaseObserver{}
		m.SetLeaseObserver(observer)
		mustAcquire(t, m, humanReq(1))
		mustAcquire(t, m, requestForResource(aiReq(2), resourceArmMain))

		gate.Trip()
		m.RevokeAll(gate.Epoch())
		if m.current(ResourceBaseMain) != nil || m.current(resourceArmMain) != nil {
			t.Fatal("RevokeAll left a resource lease")
		}
		if events := observer.snapshot(); len(events) != 0 {
			t.Fatalf("RevokeAll called observer on Safety path: %+v", events)
		}
		m.drainRevoked()
		if events := observer.snapshot(); len(events) != 2 {
			t.Fatalf("Safety notifications = %+v, want both resources", events)
		}
	})

	t.Run("stop", func(t *testing.T) {
		m, _, _ := newTestModule(t)
		mustAcquire(t, m, humanReq(1))
		mustAcquire(t, m, requestForResource(aiReq(2), resourceArmMain))

		if err := m.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if m.current(ResourceBaseMain) != nil || m.current(resourceArmMain) != nil {
			t.Fatal("Stop left a resource lease")
		}
	})
}

func TestRevokeResourceInvalidatesOnlyMatchingHandle(t *testing.T) {
	m, gate, _ := newTestModule(t)
	observer := &recordingLeaseObserver{}
	m.SetLeaseObserver(observer)
	base := mustAcquire(t, m, humanReq(1))
	arm := mustAcquire(t, m, requestForResource(aiReq(2), resourceArmMain))
	before := gate.Epoch()

	m.RevokeResource(resourceArmMain, arm.ResourceGeneration)

	if _, err := m.Check(arm.ID, arm.Conn); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("revoked resource lease check = %v, want ErrControlNotHeld", err)
	}
	if _, err := m.Check(base.ID, base.Conn); err != nil {
		t.Fatalf("resource revoke invalidated another handle: %v", err)
	}
	if gate.Epoch() != before+1 {
		t.Fatalf("resource revoke epoch = %d, want %d", gate.Epoch(), before+1)
	}
	assertSingleLeaseEnd(t, observer, arm)

	stable := gate.Epoch()
	m.RevokeResource(resourceArmMain, arm.ResourceGeneration)
	m.RevokeResource("", arm.ResourceGeneration)
	if gate.Epoch() != stable {
		t.Fatalf("idempotent resource revoke advanced epoch %d -> %d", stable, gate.Epoch())
	}
}

func TestOldResourceGenerationCannotRevokeReplacementLease(t *testing.T) {
	m, _, _ := newTestModule(t)
	old := mustAcquire(t, m, requestForResource(aiReq(1), resourceArmMain))

	replacementReq := requestForResource(aiReq(1), resourceArmMain)
	replacementReq.ResourceGeneration = old.ResourceGeneration + 1
	replacement := mustAcquire(t, m, replacementReq)
	if replacement.ID == old.ID {
		t.Fatal("resource generation replacement renewed the old lease")
	}

	m.RevokeResource(resourceArmMain, old.ResourceGeneration)
	if _, err := m.CheckResource(
		replacement.Conn, replacement.Resource, replacement.ResourceGeneration,
	); err != nil {
		t.Fatalf("old-generation revoke invalidated replacement lease: %v", err)
	}
	if _, err := m.CheckResource(
		replacement.Conn, replacement.Resource, old.ResourceGeneration,
	); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("old generation still authorized: %v", err)
	}
}

func TestResourceSlotDirectoryHasHardSafetyBound(t *testing.T) {
	m, _, _ := newTestModule(t)
	full := &slotIndex{
		byResource: make(map[string]*resourceSlot, maxResourceSlots),
		all:        make([]*resourceSlot, 0, maxResourceSlots),
	}
	for i := range maxResourceSlots {
		handle := fmt.Sprintf("resource.%d", i)
		slot := &resourceSlot{resource: handle}
		full.byResource[handle] = slot
		full.all = append(full.all, slot)
	}
	m.slots.Store(full)

	req := humanReq(99)
	req.Resource = "resource.overflow"
	if _, err := m.Acquire(req); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("Acquire beyond slot bound = %v, want ErrResourceCapacity", err)
	}
	if got := len(m.slots.Load().all); got != maxResourceSlots {
		t.Fatalf("slot directory grew to %d, want hard bound %d", got, maxResourceSlots)
	}
}

func TestSafetyNotificationCompletesBeforeSameResourceReacquire(t *testing.T) {
	m, gate, _ := newTestModule(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	m.SetLeaseObserver(blockingLeaseObserver{entered: entered, release: release})
	mustAcquire(t, m, requestForResource(humanReq(1), resourceArmMain))

	gate.Trip()
	m.RevokeAll(gate.Epoch())
	if !gate.RequireRearm() || !gate.Rearm() {
		t.Fatal("failed to re-arm gate")
	}

	drained := make(chan struct{})
	go func() {
		m.drainRevoked()
		close(drained)
	}()
	<-entered

	acquired := make(chan error, 1)
	go func() {
		_, err := m.Acquire(requestForResource(humanReq(1), resourceArmMain))
		acquired <- err
	}()
	select {
	case err := <-acquired:
		t.Fatalf("Acquire completed before old observer boundary: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	<-drained
	if err := <-acquired; err != nil {
		t.Fatalf("Acquire after observer boundary: %v", err)
	}
}

func TestSafetyFloorInvalidatesEveryResourceAfterRearm(t *testing.T) {
	m, gate, _ := newTestModule(t)
	base := mustAcquire(t, m, humanReq(1))
	arm := mustAcquire(t, m, requestForResource(aiReq(2), resourceArmMain))

	gate.Trip()
	haltEpoch := gate.Epoch()
	m.RevokeAll(haltEpoch)
	if !gate.RequireRearm() || !gate.Rearm() {
		t.Fatal("failed to re-arm gate")
	}

	for _, lease := range []Lease{base, arm} {
		if lease.Epoch >= haltEpoch {
			t.Fatalf("test setup: lease epoch %d is not before safety floor %d",
				lease.Epoch, haltEpoch)
		}
		slot := m.slot(lease.Resource)
		slot.cur.Store(new(lease))
		if _, err := m.Check(lease.ID, lease.Conn); !errors.Is(err, ErrStaleEpoch) {
			t.Fatalf("restored old %s lease check after rearm = %v, want ErrStaleEpoch",
				lease.Resource, err)
		}
		slot.cur.Store(nil)
	}

	next := mustAcquire(t, m, requestForResource(aiReq(3), resourceArmMain))
	if next.Epoch <= haltEpoch {
		t.Fatalf("new lease epoch = %d, want > safety floor %d", next.Epoch, haltEpoch)
	}
}

type blockingLeaseObserver struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (o blockingLeaseObserver) ControlLeaseEnded(ConnID, string, ID) {
	o.entered <- struct{}{}
	<-o.release
}
