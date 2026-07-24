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
	if err := m.Accept(id, 1); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("double Accept err=%v, want ErrIllegalTransition", err)
	}
	if !aud.has(actionIllegal) {
		t.Error("illegal transition must be audited")
	}
}

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

	if err := m.Progress(id, []byte("x")); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Progress while pending err=%v, want ErrNotRunning", err)
	}
	_ = m.Accept(id, 1)
	if err := m.Progress(id, []byte("x")); err != nil {
		t.Fatalf("Progress while running: %v", err)
	}
	_ = m.Succeed(id, nil)
	if err := m.Progress(id, []byte("x")); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Progress after terminal err=%v, want ErrNotRunning", err)
	}
}

func TestFail_CoercesInvalidCode(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)

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

func TestReportTerminal_Idempotency(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)
	if err := m.Succeed(id, nil); err != nil {
		t.Fatalf("Succeed: %v", err)
	}
	if err := m.Succeed(id, nil); err != nil {
		t.Fatalf("idempotent Succeed err=%v, want nil", err)
	}
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

func TestCancelledRequiresCancelRequested(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)
	if err := m.Cancelled(id); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("Cancelled from running err=%v, want ErrIllegalTransition", err)
	}
}

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
