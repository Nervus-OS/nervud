package subscription

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

// scopedKey 造一个带实例作用域的键。
func scopedKey(scope uint64) Key {
	return Key{ProviderConn: nil, EndpointID: 7, EventID: 1, Scope: scope}
}

func reliableMeta() *ipcv1.EventMeta {
	return &ipcv1.EventMeta{
		EventId:       1,
		DeliveryClass: ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE,
	}
}

// 【作用域不同即收不到】。
//
// 这是 operation 事件不泄漏给别人的全部机制：同一个内建 endpoint 上跑着全机
// 的 operation，靠 Scope 把它们分开。少了它，订阅方会收到别人的进度、
// 失败细因与资源句柄。
func TestScope_EventsStayWithinTheirInstance(t *testing.T) {
	r := New()
	alice := &collectSink{}
	bob := &collectSink{}

	r.Subscribe("alice-conn", alice, 1, scopedKey(7), reliableMeta())
	r.Subscribe("bob-conn", bob, 1, scopedKey(9), reliableMeta())

	if closed := r.Publish(scopedKey(7), []byte("op7"), 0); len(closed) != 0 {
		t.Fatalf("意外关闭了订阅: %+v", closed)
	}

	if len(alice.events) != 1 {
		t.Fatalf("alice 收到 %d 条，want 1", len(alice.events))
	}
	if len(bob.events) != 0 {
		t.Fatalf("bob 收到了不属于它的事件: %d 条", len(bob.events))
	}
}

// 同一实例的多个订阅方都收到——作用域分的是实例，不是订阅方。
func TestScope_SameInstanceFansOutToAll(t *testing.T) {
	r := New()
	a, b := &collectSink{}, &collectSink{}
	r.Subscribe("a", a, 1, scopedKey(7), reliableMeta())
	r.Subscribe("b", b, 1, scopedKey(7), reliableMeta())

	r.Publish(scopedKey(7), []byte("x"), 0)

	if len(a.events) != 1 || len(b.events) != 1 {
		t.Fatalf("扇出 = a:%d b:%d, want 1:1", len(a.events), len(b.events))
	}
}

// 【无作用域的订阅收不到有作用域的事件】。
//
// 这是 fail closed 的方向：Scope 0 表示「不分实例」，而一个带作用域的事件
// 明确说了它属于某一个实例。让 0 收到全部等于把广播又开回来。
func TestScope_UnscopedDoesNotReceiveScoped(t *testing.T) {
	r := New()
	sink := &collectSink{}
	r.Subscribe("conn", sink, 1, scopedKey(0), reliableMeta())

	r.Publish(scopedKey(7), []byte("x"), 0)

	if len(sink.events) != 0 {
		t.Fatalf("无作用域订阅收到了 %d 条有作用域的事件", len(sink.events))
	}
}

// CloseScope 只关一个实例，不碰同一 endpoint 上别的实例。
//
// operation 走到终态后就该关掉它的订阅——留着会让调用方一直等一个永远不来
// 的事件。但别人的 operation 还在跑，误杀它们比不关更糟。
func TestCloseScope_LeavesOtherInstancesAlone(t *testing.T) {
	r := New()
	seven, nine := &collectSink{}, &collectSink{}
	r.Subscribe("a", seven, 1, scopedKey(7), reliableMeta())
	r.Subscribe("b", nine, 1, scopedKey(9), reliableMeta())

	closed := r.CloseScope(nil, 7, 7,
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_ENDPOINT_DIED)
	if len(closed) != 1 {
		t.Fatalf("关闭了 %d 条订阅，want 1", len(closed))
	}
	if closed[0].Conn != "a" {
		t.Fatalf("关掉的是 %v，want a", closed[0].Conn)
	}

	// 9 号实例仍然收得到。
	r.Publish(scopedKey(9), []byte("x"), 0)
	if len(nine.events) != 1 {
		t.Fatalf("9 号实例的订阅被误杀了")
	}
	if r.Len() != 1 {
		t.Fatalf("剩余订阅 = %d, want 1", r.Len())
	}
}

// CloseProviderEndpoint 跨全部作用域——endpoint 都没了，它上面的实例自然也没了。
func TestCloseProviderEndpoint_ClosesEveryScope(t *testing.T) {
	r := New()
	r.Subscribe("a", &collectSink{}, 1, scopedKey(7), reliableMeta())
	r.Subscribe("b", &collectSink{}, 1, scopedKey(9), reliableMeta())

	closed := r.CloseProviderEndpoint(nil, 7,
		ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_ENDPOINT_DIED)
	if len(closed) != 2 {
		t.Fatalf("关闭了 %d 条，want 2（跨全部作用域）", len(closed))
	}
	if r.Len() != 0 {
		t.Fatalf("剩余订阅 = %d, want 0", r.Len())
	}
}

// collectSink 收下全部投递。
type collectSink struct {
	events []*ipcv1.Envelope
}

func (c *collectSink) Deliver(env *ipcv1.Envelope) bool {
	c.events = append(c.events, env)
	return true
}
