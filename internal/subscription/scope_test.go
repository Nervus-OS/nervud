package subscription

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

func scopedKey(scope uint64) Key {
	return Key{ProviderConn: nil, EndpointID: 7, EventID: 1, Scope: scope}
}

func reliableMeta() *ipcv1.EventMeta {
	return &ipcv1.EventMeta{
		EventId:       1,
		DeliveryClass: ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE,
	}
}

//

func TestScope_EventsStayWithinTheirInstance(t *testing.T) {
	r := New()
	alice := &collectSink{}
	bob := &collectSink{}

	r.Subscribe("alice-conn", alice, 1, scopedKey(7), reliableMeta())
	r.Subscribe("bob-conn", bob, 1, scopedKey(9), reliableMeta())

	if closed := r.Publish(scopedKey(7), []byte("op7"), 0); len(closed) != 0 {
		t.Fatalf("unexpected subscription result; value = %+v", closed)
	}

	if len(alice.events) != 1 {
		t.Fatalf("unexpected subscription result; alice %d want 1", len(alice.events))
	}
	if len(bob.events) != 0 {
		t.Fatalf("unexpected subscription result; bob: %d", len(bob.events))
	}
}

func TestScope_SameInstanceFansOutToAll(t *testing.T) {
	r := New()
	a, b := &collectSink{}, &collectSink{}
	r.Subscribe("a", a, 1, scopedKey(7), reliableMeta())
	r.Subscribe("b", b, 1, scopedKey(7), reliableMeta())

	r.Publish(scopedKey(7), []byte("x"), 0)

	if len(a.events) != 1 || len(b.events) != 1 {
		t.Fatalf("unexpected subscription result; value = a:%d b:%d, want 1:1", len(a.events), len(b.events))
	}
}

//

func TestScope_UnscopedDoesNotReceiveScoped(t *testing.T) {
	r := New()
	sink := &collectSink{}
	r.Subscribe("conn", sink, 1, scopedKey(0), reliableMeta())

	r.Publish(scopedKey(7), []byte("x"), 0)

	if len(sink.events) != 0 {
		t.Fatalf("unexpected subscription result; value = %d", len(sink.events))
	}
}

//

func TestCloseScope_LeavesOtherInstancesAlone(t *testing.T) {
	r := New()
	seven, nine := &collectSink{}, &collectSink{}
	r.Subscribe("a", seven, 1, scopedKey(7), reliableMeta())
	r.Subscribe("b", nine, 1, scopedKey(9), reliableMeta())

	closed := r.CloseScope(nil, 7, 7,
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_ENDPOINT_DIED)
	if len(closed) != 1 {
		t.Fatalf("unexpected subscription result; value = %d want 1", len(closed))
	}
	if closed[0].Conn != "a" {
		t.Fatalf("unexpected subscription result; value = %v want a", closed[0].Conn)
	}

	r.Publish(scopedKey(9), []byte("x"), 0)
	if len(nine.events) != 1 {
		t.Fatalf("unexpected subscription result; 9")
	}
	if r.Len() != 1 {
		t.Fatalf("unexpected subscription result; value = %d, want 1", r.Len())
	}
}

func TestCloseProviderEndpoint_ClosesEveryScope(t *testing.T) {
	r := New()
	r.Subscribe("a", &collectSink{}, 1, scopedKey(7), reliableMeta())
	r.Subscribe("b", &collectSink{}, 1, scopedKey(9), reliableMeta())

	closed := r.CloseProviderEndpoint(nil, 7,
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_ENDPOINT_DIED)
	if len(closed) != 2 {
		t.Fatalf("unexpected subscription result; value = %d want 2", len(closed))
	}
	if r.Len() != 0 {
		t.Fatalf("unexpected subscription result; value = %d, want 0", r.Len())
	}
}

type collectSink struct {
	events []*ipcv1.Envelope
}

func (c *collectSink) Deliver(env *ipcv1.Envelope) bool {
	c.events = append(c.events, env)
	return true
}
