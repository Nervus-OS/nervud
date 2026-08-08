package subscription

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

type fakeSink struct {
	events []*ipcv1.Event
	full   bool
}

func (f *fakeSink) Deliver(env *ipcv1.Envelope) bool {
	if f.full {
		return false
	}
	f.events = append(f.events, env.GetEvent())
	return true
}

func eventMeta(id uint32, class ipcv1.DeliveryClass) *ipcv1.EventMeta {
	return &ipcv1.EventMeta{EventId: id, DeliveryClass: class}
}

func testKey() Key {
	return Key{ProviderConn: "provider-conn", EndpointID: 7, EventID: 1}
}

func TestSubscribeAndPublish(t *testing.T) {
	r := New()
	sink := &fakeSink{}
	id := r.Subscribe("caller", sink, 99, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	if id != 1 {
		t.Fatalf("unexpected subscription result; subscription_id = %d, want 1", id)
	}

	if closed := r.Publish(testKey(), []byte("hello"), 12345); len(closed) != 0 {
		t.Fatalf("unexpected subscription result; value = %+v", closed)
	}
	if len(sink.events) != 1 {
		t.Fatalf("unexpected subscription result; value = %d, want 1", len(sink.events))
	}
	ev := sink.events[0]
	if ev.GetSubscriptionId() != id || ev.GetSequence() != 1 {
		t.Errorf("event = %+v", ev)
	}

	if ev.GetEndpointId() != 99 {
		t.Errorf("unexpected subscription result; endpoint_id = %d, want 99", ev.GetEndpointId())
	}
	if ev.GetMonotonicTimestampNanos() != 12345 {
		t.Errorf("unexpected subscription result; value = %d", ev.GetMonotonicTimestampNanos())
	}
}

//

func TestSequenceIsPerSubscription(t *testing.T) {
	r := New()
	first := &fakeSink{}
	r.Subscribe("caller-a", first, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))

	r.Publish(testKey(), nil, 0)
	r.Publish(testKey(), nil, 0)

	second := &fakeSink{}
	r.Subscribe("caller-b", second, 2, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	r.Publish(testKey(), nil, 0)

	if len(first.events) != 3 || first.events[2].GetSequence() != 3 {
		t.Fatalf("unexpected subscription result; sequence: %+v", first.events)
	}
	if len(second.events) != 1 || second.events[0].GetSequence() != 1 {
		t.Fatalf("unexpected subscription result; 1: %+v", second.events)
	}
}

//

func TestSubscriptionIDNeverReused(t *testing.T) {
	r := New()
	sink := &fakeSink{}
	first := r.Subscribe("caller", sink, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	if !r.Unsubscribe("caller", first) {
		t.Fatal("unexpected subscription result; Unsubscribe")
	}
	second := r.Subscribe("caller", sink, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	if second == first {
		t.Fatalf("unexpected subscription result; subscription_id: %d", second)
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	r := New()
	sink := &fakeSink{}
	id := r.Subscribe("caller", sink, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	r.Unsubscribe("caller", id)

	r.Publish(testKey(), nil, 0)
	if len(sink.events) != 0 {
		t.Fatalf("unexpected subscription result; value = %+v", sink.events)
	}
	if r.Len() != 0 {
		t.Errorf("Len = %d, want 0", r.Len())
	}
}

func TestReliableBackpressureClosesSubscription(t *testing.T) {
	r := New()
	sink := &fakeSink{full: true}
	id := r.Subscribe("caller", sink, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))

	closed := r.Publish(testKey(), nil, 0)
	if len(closed) != 1 {
		t.Fatalf("unexpected subscription result; closed = %+v, want 1", closed)
	}
	if closed[0].SubscriptionID != id {
		t.Errorf("closed id = %d, want %d", closed[0].SubscriptionID, id)
	}
	if closed[0].Reason !=
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_BACKPRESSURE {
		t.Errorf("reason = %v, want BACKPRESSURE", closed[0].Reason)
	}
}

func TestStateAndLossyAccumulateDropped(t *testing.T) {
	for _, class := range []ipcv1.DeliveryClass{
		ipcv1.DeliveryClass_DELIVERY_CLASS_STATE,
		ipcv1.DeliveryClass_DELIVERY_CLASS_LOSSY,
	} {
		t.Run(class.String(), func(t *testing.T) {
			r := New()
			sink := &fakeSink{full: true}
			r.Subscribe("caller", sink, 1, testKey(), eventMeta(1, class))

			for i := 0; i < 3; i++ {
				if closed := r.Publish(testKey(), nil, 0); len(closed) != 0 {
					t.Fatalf("unexpected subscription result; value = %v", class)
				}
			}

			sink.full = false
			r.Publish(testKey(), nil, 0)

			if len(sink.events) != 1 {
				t.Fatalf("unexpected subscription result; value = %d, want 1", len(sink.events))
			}
			if got := sink.events[0].GetDropped(); got != 3 {
				t.Errorf("dropped = %d, want 3", got)
			}

			if got := sink.events[0].GetSequence(); got != 4 {
				t.Errorf("unexpected subscription result; sequence = %d, want 4 dropped", got)
			}
		})
	}
}

func TestDroppedResetsAfterDelivery(t *testing.T) {
	r := New()
	sink := &fakeSink{full: true}
	r.Subscribe("caller", sink, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_LOSSY))

	r.Publish(testKey(), nil, 0)
	sink.full = false
	r.Publish(testKey(), nil, 0)
	r.Publish(testKey(), nil, 0)

	if len(sink.events) != 2 {
		t.Fatalf("unexpected subscription result; value = %d", len(sink.events))
	}
	if sink.events[0].GetDropped() != 1 {
		t.Errorf("unexpected subscription result; dropped = %d, want 1", sink.events[0].GetDropped())
	}
	if sink.events[1].GetDropped() != 0 {
		t.Errorf("unexpected subscription result; dropped = %d, want 0",
			sink.events[1].GetDropped())
	}
}

//

func TestUnspecifiedDeliveryClassFailsClosed(t *testing.T) {
	if got := DeliveryClassOf(&ipcv1.EventMeta{}); got !=
		ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE {
		t.Fatalf("unexpected subscription result; value = %v, want RELIABLE", got)
	}
	if got := DeliveryClassOf(&ipcv1.EventMeta{DeliveryClass: 99}); got !=
		ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE {
		t.Fatalf("unexpected subscription result; value = %v, want RELIABLE", got)
	}
}

func TestCloseConnRemovesOnlyThatConn(t *testing.T) {
	r := New()
	gone := &fakeSink{}
	stays := &fakeSink{}
	r.Subscribe("caller-gone", gone, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	r.Subscribe("caller-stays", stays, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))

	if ids := r.CloseConn("caller-gone"); len(ids) != 1 {
		t.Fatalf("unexpected subscription result; value = %d, want 1", len(ids))
	}
	r.Publish(testKey(), nil, 0)

	if len(gone.events) != 0 {
		t.Error("unexpected subscription result")
	}
	if len(stays.events) != 1 {
		t.Error("unexpected subscription result")
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
}

func TestCloseProviderEndpoint(t *testing.T) {
	r := New()
	affected := &fakeSink{}
	other := &fakeSink{}
	otherKey := Key{ProviderConn: "provider-conn", EndpointID: 8, EventID: 1}

	r.Subscribe("caller-a", affected, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	r.Subscribe("caller-b", other, 1, otherKey,
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))

	closed := r.CloseProviderEndpoint("provider-conn", 7,
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_ENDPOINT_DIED)
	if len(closed) != 1 {
		t.Fatalf("unexpected subscription result; closed = %+v, want 1", closed)
	}
	if closed[0].Reason !=
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_ENDPOINT_DIED {
		t.Errorf("reason = %v", closed[0].Reason)
	}

	r.Publish(otherKey, nil, 0)
	if len(other.events) != 1 {
		t.Error("unexpected subscription result; endpoint")
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
}

func TestFanOutIsIndependentPerSubscriber(t *testing.T) {
	r := New()
	fast := &fakeSink{}
	slow := &fakeSink{full: true}
	r.Subscribe("caller-fast", fast, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_LOSSY))
	r.Subscribe("caller-slow", slow, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_LOSSY))

	r.Publish(testKey(), nil, 0)
	r.Publish(testKey(), nil, 0)

	if len(fast.events) != 2 {
		t.Fatalf("unexpected subscription result; value = %d, want 2", len(fast.events))
	}
	if fast.events[1].GetDropped() != 0 {
		t.Error("unexpected subscription result; dropped")
	}
}
