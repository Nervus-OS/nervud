package operation

import (
	"testing"
	"time"
)

func TestSafetySupersede_ConvergesRunningMotionOp(t *testing.T) {
	m, aud, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1) // MotionEpoch=1
	_ = m.Accept(id, 1)

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

func TestSafetySupersede_NewerEpochUntouched(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 3) // MotionEpoch=3
	_ = m.Accept(id, 3)

	m.SafetySupersede(3)
	m.convergeSupersede()

	if op, _ := m.Get(testCaller(), id); op.State != StateRunning {
		t.Fatalf("op at boundary epoch state=%v, want running", op.State)
	}
}

func TestSafetySupersede_DoesNotBlockOnHeldLock(t *testing.T) {
	m, _, _ := newTestManager(t, true)

	m.mu.Lock()
	done := make(chan struct{})
	go func() {
		m.SafetySupersede(9)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		m.mu.Unlock()
		t.Fatal("SafetySupersede blocked while the Manager lock was held - Safety path is being dragged")
	}
	m.mu.Unlock()
}

func TestSafetySupersede_BlockingSubscriberDoesNotStall(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)

	ch, cancel := m.Subscribe(testCaller(), id)
	defer cancel()
	for i := 0; i < subBuffer+8; i++ {
		_ = m.Progress(id, []byte("fill"))
	}
	_ = ch

	m.SafetySupersede(2)
	done := make(chan struct{})
	go func() {
		m.convergeSupersede()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("convergeSupersede stalled behind a blocking subscriber - fan-out must never back-pressure")
	}
	if op, _ := m.Get(testCaller(), id); op.State != StateFailed {
		t.Fatalf("state=%v, want failed despite blocking subscriber", op.State)
	}
}
