package operation

import (
	"testing"
	"time"
)

// TestSafetySupersede_ConvergesRunningMotionOp Safety 触发把边界之前在跑的运动类
// operation 收敛为 FAILED（被接管）。
func TestSafetySupersede_ConvergesRunningMotionOp(t *testing.T) {
	m, aud, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1) // MotionEpoch=1
	_ = m.Accept(id, 1)

	// Safety 递增到 epoch=2：MotionEpoch(1) < 2 → 被接管。
	m.SafetySupersede(2)
	m.convergeSupersede()

	op, _ := m.Get(testCaller(), id)
	if op.State != StateFailed || op.TerminalStatus != preconCode {
		t.Fatalf("state=%v status=%v, want failed/FAILED_PRECONDITION", op.State, op.TerminalStatus)
	}
	if !aud.has(actionSafetySuperseded) {
		t.Error("safety supersede must be audited")
	}
}

// TestSafetySupersede_NonMotionUntouched 非运动类 operation（无 lease）不受物理
// Safety 边界影响，不被 supersede 收敛。
func TestSafetySupersede_NonMotionUntouched(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id, code := m.Create(nil, testCaller(), testOrigin(), []string{testResource}, 0, 0, m.now().Add(time.Minute))
	if code != acceptedCode {
		t.Fatalf("Create non-motion: %v", code)
	}
	_ = m.Accept(id, 0)

	m.SafetySupersede(5)
	m.convergeSupersede()

	if op, _ := m.Get(testCaller(), id); op.State != StateRunning {
		t.Fatalf("non-motion op state=%v, want running (untouched by safety)", op.State)
	}
}

// TestSafetySupersede_NewerEpochUntouched 边界之后创建的 operation（MotionEpoch >=
// boundary）不被旧边界收敛。
func TestSafetySupersede_NewerEpochUntouched(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 3) // MotionEpoch=3
	_ = m.Accept(id, 3)

	m.SafetySupersede(3) // boundary=3；MotionEpoch(3) >= 3 → 不接管
	m.convergeSupersede()

	if op, _ := m.Get(testCaller(), id); op.State != StateRunning {
		t.Fatalf("op at boundary epoch state=%v, want running", op.State)
	}
}

// TestSafetySupersede_DoesNotBlockOnHeldLock 是铁律 4 的核心证明：即便有一个慢
// operation 正持有 Manager 锁（模拟正在做 I/O 的 Create/report），SafetySupersede
// 也必须立刻返回——它只做原子写 + 非阻塞投递，绝不取 mu，因此 Safety Lane 不被拖住。
func TestSafetySupersede_DoesNotBlockOnHeldLock(t *testing.T) {
	m, _, _ := newTestManager(t, true)

	m.mu.Lock() // 模拟慢 operation 持锁
	done := make(chan struct{})
	go func() {
		m.SafetySupersede(9)
		close(done)
	}()

	select {
	case <-done:
		// 好：即便锁被占，SafetySupersede 仍立刻返回。
	case <-time.After(2 * time.Second):
		m.mu.Unlock()
		t.Fatal("SafetySupersede blocked while the Manager lock was held — Safety path is being dragged")
	}
	m.mu.Unlock()
}

// TestSafetySupersede_BlockingSubscriberDoesNotStall 会阻塞的慢订阅者（填满且从不
// 读取的订阅通道）不能拖住 Safety 收敛：fan-out 是非阻塞发送，满即丢弃（§9）。
func TestSafetySupersede_BlockingSubscriberDoesNotStall(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)

	// 订阅但从不读取；灌满缓冲，制造"会阻塞的 fake 订阅者"。
	ch, cancel := m.Subscribe(testCaller(), id)
	defer cancel()
	for i := 0; i < subBuffer+8; i++ {
		_ = m.Progress(id, []byte("fill"))
	}
	_ = ch // 有意不读

	m.SafetySupersede(2)
	done := make(chan struct{})
	go func() {
		m.convergeSupersede()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("convergeSupersede stalled behind a blocking subscriber — fan-out must never back-pressure")
	}
	if op, _ := m.Get(testCaller(), id); op.State != StateFailed {
		t.Fatalf("state=%v, want failed despite blocking subscriber", op.State)
	}
}
