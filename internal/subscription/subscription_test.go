package subscription

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

// fakeSink 记录收到的 Event，并可以模拟队列满。
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
		t.Fatalf("第一个 subscription_id = %d, want 1", id)
	}

	if closed := r.Publish(testKey(), []byte("hello"), 12345); len(closed) != 0 {
		t.Fatalf("不该有订阅被关闭: %+v", closed)
	}
	if len(sink.events) != 1 {
		t.Fatalf("收到 %d 条事件, want 1", len(sink.events))
	}
	ev := sink.events[0]
	if ev.GetSubscriptionId() != id || ev.GetSequence() != 1 {
		t.Errorf("event = %+v", ev)
	}
	// 【endpoint_id 必须是订阅方自己那个句柄】，不是 Provider 侧的。
	// 混用会让订阅方路由到一个它从没见过的 endpoint
	if ev.GetEndpointId() != 99 {
		t.Errorf("endpoint_id = %d, want 99（订阅方句柄）", ev.GetEndpointId())
	}
	if ev.GetMonotonicTimestampNanos() != 12345 {
		t.Errorf("时间戳没有透传: %d", ev.GetMonotonicTimestampNanos())
	}
}

// sequence 是【本订阅内】的第几条，不是全局序号。
//
// 用全局序号的话，一个中途加入的订阅方会看到从一个巨大数字开始的序列，
// 而它无从判断前面那些是「没订上」还是「丢了」。
func TestSequenceIsPerSubscription(t *testing.T) {
	r := New()
	first := &fakeSink{}
	r.Subscribe("caller-a", first, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))

	r.Publish(testKey(), nil, 0)
	r.Publish(testKey(), nil, 0)

	// 第二个订阅方在两条事件之后才加入
	second := &fakeSink{}
	r.Subscribe("caller-b", second, 2, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	r.Publish(testKey(), nil, 0)

	if len(first.events) != 3 || first.events[2].GetSequence() != 3 {
		t.Fatalf("先加入的订阅方 sequence 不对: %+v", first.events)
	}
	if len(second.events) != 1 || second.events[0].GetSequence() != 1 {
		t.Fatalf("后加入的订阅方应当从 1 开始: %+v", second.events)
	}
}

// 【句柄永不复用】：退订之后再订，拿到的是新号。
//
// 复用会让退订后到达的在途 Event 被错认成新订阅的数据——数字对得上、连接也
// 对得上，接收方没有任何办法分辨。
func TestSubscriptionIDNeverReused(t *testing.T) {
	r := New()
	sink := &fakeSink{}
	first := r.Subscribe("caller", sink, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	if !r.Unsubscribe("caller", first) {
		t.Fatal("Unsubscribe 报告不存在")
	}
	second := r.Subscribe("caller", sink, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	if second == first {
		t.Fatalf("subscription_id 被复用: %d", second)
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
		t.Fatalf("退订后仍收到事件: %+v", sink.events)
	}
	if r.Len() != 0 {
		t.Errorf("Len = %d, want 0", r.Len())
	}
}

// 【RELIABLE 投递不下时终止订阅，不静默丢弃】。
func TestReliableBackpressureClosesSubscription(t *testing.T) {
	r := New()
	sink := &fakeSink{full: true}
	id := r.Subscribe("caller", sink, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))

	closed := r.Publish(testKey(), nil, 0)
	if len(closed) != 1 {
		t.Fatalf("closed = %+v, want 1 条", closed)
	}
	if closed[0].SubscriptionID != id {
		t.Errorf("closed id = %d, want %d", closed[0].SubscriptionID, id)
	}
	if closed[0].Reason !=
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_BACKPRESSURE {
		t.Errorf("reason = %v, want BACKPRESSURE", closed[0].Reason)
	}
}

// STATE / LOSSY 投递不下时不终止订阅，把丢掉的条数记进 dropped 让下一条带上。
func TestStateAndLossyAccumulateDropped(t *testing.T) {
	for _, class := range []ipcv1.DeliveryClass{
		ipcv1.DeliveryClass_DELIVERY_CLASS_STATE,
		ipcv1.DeliveryClass_DELIVERY_CLASS_LOSSY,
	} {
		t.Run(class.String(), func(t *testing.T) {
			r := New()
			sink := &fakeSink{full: true}
			r.Subscribe("caller", sink, 1, testKey(), eventMeta(1, class))

			// 三条都投不下
			for i := 0; i < 3; i++ {
				if closed := r.Publish(testKey(), nil, 0); len(closed) != 0 {
					t.Fatalf("%v 不该因背压被关闭", class)
				}
			}
			// 队列腾出来了，下一条必须带上前面丢掉的条数
			sink.full = false
			r.Publish(testKey(), nil, 0)

			if len(sink.events) != 1 {
				t.Fatalf("收到 %d 条, want 1", len(sink.events))
			}
			if got := sink.events[0].GetDropped(); got != 3 {
				t.Errorf("dropped = %d, want 3", got)
			}
			// sequence 已经为每条递增过，所以缺口与 dropped 对得上
			if got := sink.events[0].GetSequence(); got != 4 {
				t.Errorf("sequence = %d, want 4（缺口要与 dropped 对得上）", got)
			}
		})
	}
}

// 投递成功后 dropped 清零——它描述的是「这条与上一条之间发生了什么」。
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
		t.Fatalf("收到 %d 条", len(sink.events))
	}
	if sink.events[0].GetDropped() != 1 {
		t.Errorf("第一条 dropped = %d, want 1", sink.events[0].GetDropped())
	}
	if sink.events[1].GetDropped() != 0 {
		t.Errorf("第二条 dropped = %d, want 0（成功投递后必须清零）",
			sink.events[1].GetDropped())
	}
}

// 【未指定的 delivery_class fail closed 为 RELIABLE】。
//
// RELIABLE 是最严的一档。把漏填当成「可以随便丢」才是危险的默认：
// 客户端会以为自己拿到了完整序列。
func TestUnspecifiedDeliveryClassFailsClosed(t *testing.T) {
	if got := DeliveryClassOf(&ipcv1.EventMeta{}); got !=
		ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE {
		t.Fatalf("未指定 = %v, want RELIABLE", got)
	}
	if got := DeliveryClassOf(&ipcv1.EventMeta{DeliveryClass: 99}); got !=
		ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE {
		t.Fatalf("未知值 = %v, want RELIABLE", got)
	}
}

// 订阅方断开时清掉它名下全部订阅，并且不影响别的订阅方。
func TestCloseConnRemovesOnlyThatConn(t *testing.T) {
	r := New()
	gone := &fakeSink{}
	stays := &fakeSink{}
	r.Subscribe("caller-gone", gone, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))
	r.Subscribe("caller-stays", stays, 1, testKey(),
		eventMeta(1, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE))

	if ids := r.CloseConn("caller-gone"); len(ids) != 1 {
		t.Fatalf("清掉 %d 条, want 1", len(ids))
	}
	r.Publish(testKey(), nil, 0)

	if len(gone.events) != 0 {
		t.Error("已断开的订阅方仍收到事件")
	}
	if len(stays.events) != 1 {
		t.Error("别的订阅方被连累了")
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
}

// endpoint 失效时终止指向它的全部订阅——那之后再也不会有事件，
// 让订阅方一直等着比明确告诉它更糟。
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
		t.Fatalf("closed = %+v, want 1 条", closed)
	}
	if closed[0].Reason !=
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_ENDPOINT_DIED {
		t.Errorf("reason = %v", closed[0].Reason)
	}

	// 另一个 endpoint 的订阅不受影响
	r.Publish(otherKey, nil, 0)
	if len(other.events) != 1 {
		t.Error("别的 endpoint 的订阅被连累了")
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
}

// 同一个 key 上的多个订阅者各自独立计数、独立背压。
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

	// 慢的那个投不下不影响快的
	if len(fast.events) != 2 {
		t.Fatalf("快订阅方收到 %d 条, want 2", len(fast.events))
	}
	if fast.events[1].GetDropped() != 0 {
		t.Error("快订阅方不该有 dropped")
	}
}
