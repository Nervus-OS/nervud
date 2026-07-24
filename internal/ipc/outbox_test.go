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
		t.Fatal("push 不该在有余量时失败")
	}

	got1, ok := q.pop()
	if !ok || got1.GetPing().GetNonce() != 1 {
		t.Fatalf("pop 顺序错误: %+v", got1)
	}
	got2, ok := q.pop()
	if !ok || got2.GetPing().GetNonce() != 2 {
		t.Fatalf("pop 顺序错误: %+v", got2)
	}
}

func TestOutboundQueue_ByteBoundRejectsOverflow(t *testing.T) {
	env := pingEnv(1)
	size := proto.Size(env)

	// 容量正好放下一条,第二条必须被拒——验证限界按字节数而不是按条数
	q := newOutboundQueue(size)
	if !q.push(env) {
		t.Fatal("首条 push 应当成功")
	}
	if q.push(pingEnv(2)) {
		t.Fatal("超出字节上限的 push 应当失败")
	}

	// 弹出第一条腾出空间后,应当能再 push 一条
	if _, ok := q.pop(); !ok {
		t.Fatal("pop 应当成功")
	}
	if !q.push(pingEnv(3)) {
		t.Fatal("腾出空间后 push 应当成功")
	}
}

func TestOutboundQueue_PushAfterCloseFails(t *testing.T) {
	q := newOutboundQueue(1 << 20)
	q.close()
	if q.push(pingEnv(1)) {
		t.Fatal("已关闭的队列不该接受新 push")
	}
}

func TestOutboundQueue_CloseWakesBlockedPop(t *testing.T) {
	q := newOutboundQueue(1 << 20)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, ok := q.pop(); ok {
			t.Error("空且已关闭的队列,pop 应当返回 ok=false")
		}
	}()

	select {
	case <-done:
		t.Fatal("pop 不该在 close 之前返回")
	case <-time.After(50 * time.Millisecond):
	}

	q.close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("close 没有唤醒阻塞中的 pop")
	}
}

// close 之后仍应把已经排队的内容排空,而不是直接截断——正常收尾场景下最后一个
// Response 不能因为紧跟着的 close 调用而丢失
func TestOutboundQueue_CloseDrainsExistingItems(t *testing.T) {
	q := newOutboundQueue(1 << 20)
	if !q.push(pingEnv(7)) {
		t.Fatal("push 应当成功")
	}
	q.close()

	env, ok := q.pop()
	if !ok || env.GetPing().GetNonce() != 7 {
		t.Fatalf("close 前已排队的条目应当仍可被弹出: %+v, ok=%v", env, ok)
	}

	if _, ok := q.pop(); ok {
		t.Fatal("排空后再次 pop 应当返回 ok=false")
	}
}

func TestOutboundQueue_CloseIdempotent(t *testing.T) {
	q := newOutboundQueue(1 << 20)
	q.close()
	q.close() // 不该 panic 或死锁
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
		t.Fatalf("并发 push 成功数 = %d, want %d", ok, n)
	}

	// 关闭后 pop 会先弹尽已排队条目再返回 ok=false（见 outbox.go 的 pop/close
	// 语义:close 只挡新 push,不截断已排队内容）。不 close 的话,排空后的 pop 会
	// 永久阻塞在 <-q.wake 上——开放且已空的队列 pop 阻塞是【正确】行为,漏 close
	// 才是测试自身的缺陷
	q.close()

	got := 0
	for {
		if _, ok := q.pop(); !ok {
			break
		}
		got++
	}
	if got != n {
		t.Fatalf("pop 出的条目数 = %d, want %d", got, n)
	}
}
