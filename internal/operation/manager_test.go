package operation

import (
	"context"
	"testing"
	"time"
)

func TestCreate_Validation(t *testing.T) {
	t.Run("no resources", func(t *testing.T) {
		m, aud, _ := newTestManager(t, true)
		id, code := m.Create(nil, testCaller(), testOrigin(), nil, 0, 0, m.now().Add(time.Minute))
		if code != invalidCode || id != 0 {
			t.Fatalf("empty resources: id=%d code=%v, want 0/INVALID_ARGUMENT", id, code)
		}
		if !aud.has(actionCreateRejected) {
			t.Error("rejected Create must be audited")
		}
	})

	t.Run("empty handle", func(t *testing.T) {
		m, _, _ := newTestManager(t, true)
		_, code := m.Create(nil, testCaller(), testOrigin(), []string{""}, 0, 0, m.now().Add(time.Minute))
		if code != invalidCode {
			t.Fatalf("empty handle: code=%v, want INVALID_ARGUMENT", code)
		}
	})

	t.Run("unknown resource", func(t *testing.T) {
		m, _, _ := newTestManager(t, true)
		_, code := m.Create(nil, testCaller(), testOrigin(), []string{"no.such"}, 0, 0, m.now().Add(time.Minute))
		if code != preconCode {
			t.Fatalf("unknown resource: code=%v, want FAILED_PRECONDITION", code)
		}
	})

	t.Run("motion without lease validator", func(t *testing.T) {
		aud := &fakeAuditor{}
		m := New(fakeResource{valid: map[string]bool{testResource: true}}, nil, aud, discardLog())
		_, code := m.Create(nil, testCaller(), testOrigin(), []string{testResource}, 42, 1, m.now().Add(time.Minute))
		if code != preconCode {
			t.Fatalf("motion w/o validator: code=%v, want FAILED_PRECONDITION (fail-closed)", code)
		}
	})

	t.Run("motion with invalid lease", func(t *testing.T) {
		m, _, _ := newTestManager(t, false) // lease validator rejects
		_, code := m.Create(nil, testCaller(), testOrigin(), []string{testResource}, 42, 1, m.now().Add(time.Minute))
		if code != preconCode {
			t.Fatalf("invalid lease: code=%v, want FAILED_PRECONDITION", code)
		}
	})

	t.Run("expired deadline", func(t *testing.T) {
		m, _, _ := newTestManager(t, true)
		_, code := m.Create(nil, testCaller(), testOrigin(), []string{testResource}, 0, 0, m.now().Add(-time.Second))
		if code != invalidCode {
			t.Fatalf("past deadline: code=%v, want INVALID_ARGUMENT", code)
		}
	})

	t.Run("far-future deadline", func(t *testing.T) {
		m, _, _ := newTestManager(t, true)
		_, code := m.Create(nil, testCaller(), testOrigin(), []string{testResource}, 0, 0, m.now().Add(2*time.Hour))
		if code != invalidCode {
			t.Fatalf("absurd deadline: code=%v, want INVALID_ARGUMENT", code)
		}
	})

	t.Run("happy non-motion", func(t *testing.T) {
		m, aud, _ := newTestManager(t, true)
		id, code := m.Create(nil, testCaller(), testOrigin(), []string{testResource}, 0, 0, m.now().Add(time.Minute))
		if code != acceptedCode || id == 0 {
			t.Fatalf("non-motion happy: id=%d code=%v", id, code)
		}
		op, ok := m.Get(testCaller(), id)
		if !ok || op.State != StatePending {
			t.Fatalf("created op state=%v ok=%v, want pending", op.State, ok)
		}
		if !aud.has(actionCreated) {
			t.Error("successful Create must be audited")
		}
	})

	t.Run("happy motion", func(t *testing.T) {
		m, _, _ := newTestManager(t, true)
		id := createMotion(t, m, nil, testCaller(), 1)
		op, _ := m.Get(testCaller(), id)
		if op.LeaseID != 42 || op.MotionEpoch != 1 {
			t.Fatalf("motion op lease=%d epoch=%d, want 42/1", op.LeaseID, op.MotionEpoch)
		}
	})
}

func TestCreate_MonotonicIDs(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	var prev uint64
	for i := 0; i < 5; i++ {
		id, code := m.Create(nil, testCaller(), testOrigin(), []string{testResource}, 0, 0, m.now().Add(time.Minute))
		if code != acceptedCode {
			t.Fatalf("Create %d: code=%v", i, code)
		}
		if id <= prev {
			t.Fatalf("id not monotonic: %d after %d", id, prev)
		}
		prev = id
	}
}

func TestVisibility(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)

	if _, ok := m.Get(testCaller(), id); !ok {
		t.Fatal("owner must see its own operation")
	}
	if _, ok := m.Get(otherCaller(), id); ok {
		t.Fatal("cross-caller Get must return not-found")
	}
	if code := m.Cancel(otherCaller(), id); code != notFoundCode {
		t.Fatalf("cross-caller Cancel code=%v, want NOT_FOUND", code)
	}
	if _, ok := m.Get(systemCaller(), id); !ok {
		t.Fatal("system caller must see any operation")
	}
	ch, cancel := m.Subscribe(otherCaller(), id)
	defer cancel()
	if _, open := <-ch; open {
		t.Fatal("cross-caller Subscribe must return a closed channel")
	}
}

func TestCancel_ThenProviderCancelled(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	if err := m.Accept(id, 1); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if code := m.Cancel(testCaller(), id); code != acceptedCode {
		t.Fatalf("Cancel code=%v, want ACCEPTED", code)
	}
	if op, _ := m.Get(testCaller(), id); op.State != StateCancelRequested {
		t.Fatalf("state=%v, want cancel_requested", op.State)
	}
	if err := m.Cancelled(id); err != nil {
		t.Fatalf("Cancelled: %v", err)
	}
	op, _ := m.Get(testCaller(), id)
	if op.State != StateCancelled || op.TerminalStatus != cancelledCode {
		t.Fatalf("state=%v status=%v, want cancelled/CANCELLED", op.State, op.TerminalStatus)
	}
}

func TestSucceedBeforeCancelArrives(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)
	if err := m.Succeed(id, []byte("done")); err != nil {
		t.Fatalf("Succeed: %v", err)
	}
	if code := m.Cancel(testCaller(), id); code != acceptedCode {
		t.Fatalf("late Cancel code=%v, want ACCEPTED (received, but no-op)", code)
	}
	op, _ := m.Get(testCaller(), id)
	if op.State != StateSucceeded {
		t.Fatalf("state=%v, want succeeded (terminal not overwritten)", op.State)
	}
	if string(op.TerminalResult) != "done" {
		t.Fatalf("result=%q, want done", op.TerminalResult)
	}
}

func TestDeadlineExceeded(t *testing.T) {
	m, aud, clk := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)

	m.scanDeadlines()
	if op, _ := m.Get(testCaller(), id); op.State != StateRunning {
		t.Fatalf("before deadline state=%v, want running", op.State)
	}

	clk.advance(2 * time.Minute)
	m.scanDeadlines()
	op, _ := m.Get(testCaller(), id)
	if op.State != StateFailed || op.TerminalStatus != deadlineCode {
		t.Fatalf("state=%v status=%v, want failed/DEADLINE_EXCEEDED", op.State, op.TerminalStatus)
	}
	if !aud.has(actionDeadlineExceeded) {
		t.Error("deadline timeout must be audited")
	}
}

func TestReleaseByConn(t *testing.T) {
	m, aud, _ := newTestManager(t, true)
	connA := "conn-A"
	connB := "conn-B"
	idA := createMotion(t, m, connA, testCaller(), 1)
	idB := createMotion(t, m, connB, testCaller(), 1)
	_ = m.Accept(idA, 1)
	_ = m.Accept(idB, 1)

	m.ReleaseByConn(connA)

	opA, _ := m.Get(testCaller(), idA)
	if opA.State != StateFailed {
		t.Fatalf("conn-A op state=%v, want failed (converged)", opA.State)
	}
	opB, _ := m.Get(testCaller(), idB)
	if opB.State != StateRunning {
		t.Fatalf("conn-B op state=%v, want running (untouched)", opB.State)
	}
	if !aud.has(actionConnClosed) {
		t.Error("conn cleanup must be audited")
	}
}

func TestSubscribe_ReceivesEventsAndClosesOnTerminal(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	id := createMotion(t, m, nil, testCaller(), 1)
	ch, cancel := m.Subscribe(testCaller(), id)
	defer cancel()

	_ = m.Accept(id, 1)
	if ev := <-ch; ev.Kind != EventState || ev.State != StateRunning {
		t.Fatalf("first event = %+v, want state/running", ev)
	}
	if err := m.Progress(id, []byte("50%")); err != nil {
		t.Fatalf("Progress: %v", err)
	}
	ev := <-ch
	if ev.Kind != EventProgress || string(ev.Payload) != "50%" {
		t.Fatalf("progress event = %+v", ev)
	}
	if ev.Origin.InterfaceID != "nervus.manipulator" {
		t.Fatalf("event must carry origin binding, got %+v", ev.Origin)
	}

	_ = m.Succeed(id, nil)
	got := false
	for e := range ch {
		if e.Kind == EventState && e.State == StateSucceeded {
			got = true
		}
	}
	if !got {
		t.Fatal("did not observe terminal succeeded event before channel closed")
	}
}

func TestModule_StartStopConvergesInflight(t *testing.T) {
	m, aud, _ := newTestManager(t, true)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	id := createMotion(t, m, nil, testCaller(), 1)
	_ = m.Accept(id, 1)

	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	op, _ := m.Get(testCaller(), id)
	if op.State != StateFailed {
		t.Fatalf("after Stop state=%v, want failed (shutdown converged)", op.State)
	}
	if !aud.has(actionShutdown) {
		t.Error("shutdown convergence must be audited")
	}
}

func TestStop_RejectsNewCreate(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	_, code := m.Create(nil, testCaller(), testOrigin(), []string{testResource}, 0, 0, m.now().Add(time.Minute))
	if code == acceptedCode {
		t.Fatal("Create after Stop must be rejected")
	}
}

func TestModule_Name(t *testing.T) {
	m, _, _ := newTestManager(t, true)
	if m.Name() != "operation" {
		t.Fatalf("Name()=%q, want operation", m.Name())
	}
}
