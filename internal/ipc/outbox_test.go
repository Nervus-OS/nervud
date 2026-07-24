package ipc

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func TestOutboundQueue_PushPopOrder(t *testing.T) {
	q := newOutboundQueue(1 << 20)

	a := pingEnv(1)
	b := pingEnv(2)
	if !q.push(a) || !q.push(b) {
		t.Fatal("push should not fail while capacity remains")
	}

	got1, ok := q.pop()
	if !ok || got1.GetPing().GetNonce() != 1 {
		t.Fatalf("incorrect pop order: %+v", got1)
	}
	got2, ok := q.pop()
	if !ok || got2.GetPing().GetNonce() != 2 {
		t.Fatalf("incorrect pop order: %+v", got2)
	}
}

func TestOutboundQueue_ByteBoundRejectsOverflow(t *testing.T) {
	env := pingEnv(1)
	size := proto.Size(env)

	q := newOutboundQueue(size)
	if !q.push(env) {
		t.Fatal("the first push should succeed")
	}
	if q.push(pingEnv(2)) {
		t.Fatal("a push beyond the byte limit should fail")
	}

	if _, ok := q.pop(); !ok {
		t.Fatal("pop should succeed")
	}
	if !q.push(pingEnv(3)) {
		t.Fatal("push should succeed after space is freed")
	}
}

func TestOutboundQueue_PushAfterCloseFails(t *testing.T) {
	q := newOutboundQueue(1 << 20)
	q.close()
	if q.push(pingEnv(1)) {
		t.Fatal("a closed queue should reject new pushes")
	}
}

func TestOutboundQueue_CloseWakesBlockedPop(t *testing.T) {
	q := newOutboundQueue(1 << 20)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, ok := q.pop(); ok {
			t.Error("pop on an empty closed queue should return ok=false")
		}
	}()

	select {
	case <-done:
		t.Fatal("pop should not return before close")
	case <-time.After(50 * time.Millisecond):
	}

	q.close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not wake a blocked pop")
	}
}

func TestOutboundQueue_CloseDrainsExistingItems(t *testing.T) {
	q := newOutboundQueue(1 << 20)
	if !q.push(pingEnv(7)) {
		t.Fatal("push should succeed")
	}
	q.close()

	env, ok := q.pop()
	if !ok || env.GetPing().GetNonce() != 7 {
		t.Fatalf("an item queued before close should still be returned: %+v, ok=%v", env, ok)
	}

	if _, ok := q.pop(); ok {
		t.Fatal("pop after draining should return ok=false")
	}
}

func TestOutboundQueue_CloseIdempotent(t *testing.T) {
	q := newOutboundQueue(1 << 20)
	q.close()
	q.close()
}

func TestOutboundQueue_ConcurrentPushFromMultipleGoroutines(t *testing.T) {
	q := newOutboundQueue(1 << 20)
	const n = 50

	done := make(chan bool, n)
	for i := 0; i < n; i++ {
		go func(i int) { done <- q.push(pingEnv(uint64(i))) }(i)
	}
	ok := 0
	for i := 0; i < n; i++ {
		if <-done {
			ok++
		}
	}
	if ok != n {
		t.Fatalf("successful concurrent pushes = %d, want %d", ok, n)
	}

	q.close()

	got := 0
	for {
		if _, ok := q.pop(); !ok {
			break
		}
		got++
	}
	if got != n {
		t.Fatalf("popped item count = %d, want %d", got, n)
	}
}
