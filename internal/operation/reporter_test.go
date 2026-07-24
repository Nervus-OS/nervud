package operation

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAccept_Transitions(t *testing.T) {
	m, aud, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)

	if err := m.Accept(id, 1); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if op, _ := m.Get(testCaller(), id); op.State != StateRunning {
		t.Fatalf("state=%v, want running", op.State)
	}
	// 二次 Accept 是非法转移（RUNNING→RUNNING 不在允许集合）→ 记审计并拒绝。
	if err := m.Accept(id, 1); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("double Accept err=%v, want ErrIllegalTransition", err)
	}
	if !aud.has(actionIllegal) {
		t.Error("illegal transition must be audited")
	}
}

// TestAccept_StaleEpoch Provider 报告的 epoch 与创建时绑定的不符 → 失败收敛，
// 不进入 RUNNING（铁律 1：系统取消/撤销后不得继续控制资源）。
func TestAccept_StaleEpoch(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)

	if err := m.Accept(id, 2); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale Accept err=%v, want ErrStaleEpoch", err)
	}
	op, _ := m.Get(testCaller(), id)
	if op.State != StateFailed || op.TerminalStatus != preconCode {
		t.Fatalf("state=%v status=%v, want failed/FAILED_PRECONDITION", op.State, op.TerminalStatus)
	}
}

func TestProgress_OnlyWhenRunning(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)

	// PENDING 阶段无进度。
	if err := m.Progress(id, []byte("x")); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Progress while pending err=%v, want ErrNotRunning", err)
	}
	_ = m.Accept(id, 1)
	if err := m.Progress(id, []byte("x")); err != nil {
		t.Fatalf("Progress while running: %v", err)
	}
	_ = m.Succeed(id, nil)
	// 终态后无进度。
	if err := m.Progress(id, []byte("x")); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Progress after terminal err=%v, want ErrNotRunning", err)
	}
}

func TestFail_CoercesInvalidCode(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)

	// OK 不是合法的 FAILED code：必须 fail-closed 收敛为 INTERNAL，绝不静默当成功。
	if err := m.Fail(id, okCode, []byte("boom")); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	op, _ := m.Get(testCaller(), id)
	if op.State != StateFailed {
		t.Fatalf("state=%v, want failed", op.State)
	}
	if op.TerminalStatus != internalCode {
		t.Fatalf("coerced status=%v, want INTERNAL", op.TerminalStatus)
	}
	if string(op.TerminalError) != "boom" {
		t.Fatalf("terminal error=%q, want boom", op.TerminalError)
	}
}

// TestReportTerminal_Idempotency 同终态重复回报是 no-op(nil)；异终态回报被拒
// （ErrAlreadyTerminal，终态只写一次）。
func TestReportTerminal_Idempotency(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)
	if err := m.Succeed(id, nil); err != nil {
		t.Fatalf("Succeed: %v", err)
	}
	// 同终态重复 → no-op nil。
	if err := m.Succeed(id, nil); err != nil {
		t.Fatalf("idempotent Succeed err=%v, want nil", err)
	}
	// 异终态 → 拒绝，终态不被覆盖。
	if err := m.Fail(id, internalCode, nil); !errors.Is(err, ErrAlreadyTerminal) {
		t.Fatalf("Fail after Succeed err=%v, want ErrAlreadyTerminal", err)
	}
	if op, _ := m.Get(testCaller(), id); op.State != StateSucceeded {
		t.Fatalf("state=%v, want succeeded (unchanged)", op.State)
	}
}

func TestReporter_NotFound(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	if err := m.Accept(999, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Accept unknown err=%v, want ErrNotFound", err)
	}
	if err := m.Succeed(999, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Succeed unknown err=%v, want ErrNotFound", err)
	}
}

// TestCancelledRequiresCancelRequested Provider 只能在 CANCEL_REQUESTED 之后确认
// 取消；RUNNING 直接 Cancelled 是非法转移。
func TestCancelledRequiresCancelRequested(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)
	if err := m.Cancelled(id); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("Cancelled from running err=%v, want ErrIllegalTransition", err)
	}
}

// TestTerminalOnce_Concurrent 终态只写一次（铁律 2 / spec §10）：从 CANCEL_REQUESTED
// 并发发起 Succeed/Fail/Cancelled（三者从 CANCEL_REQUESTED 都合法），只有一个生效，
// 另两个被 CAS 拒为 ErrAlreadyTerminal。跑多轮加压，配合 -race。
func TestTerminalOnce_Concurrent(t *testing.T) {
	for round := 0; round < 200; round++ {
		m, _, _ := newTestManager(t, true)
		id := createMotion(t, m, nil, testCaller(), 1)
		_ = m.Accept(id, 1)
		if code := m.Cancel(testCaller(), id); code != acceptedCode {
			t.Fatalf("Cancel: %v", code)
		}

		var winners atomic.Int32
		var wg sync.WaitGroup
		attempts := []func() error{
			func() error { return m.Succeed(id, nil) },
			func() error { return m.Fail(id, internalCode, nil) },
			func() error { return m.Cancelled(id) },
		}
		wg.Add(len(attempts))
		for _, fn := range attempts {
			go func(f func() error) {
				defer wg.Done()
				if err := f(); err == nil {
					winners.Add(1)
				}
			}(fn)
		}
		wg.Wait()

		if got := winners.Load(); got != 1 {
			t.Fatalf("round %d: %d winners, want exactly 1 (terminal written once)", round, got)
		}
		op, _ := m.Get(testCaller(), id)
		if !op.State.Terminal() {
			t.Fatalf("round %d: final state=%v, want terminal", round, op.State)
		}
	}
}
