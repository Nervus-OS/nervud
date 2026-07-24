package control

import (
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

func TestCheckAndRefreshAreAllocationFree(t *testing.T) {
	pol := Policy{
		Human: ClassPolicy{TTL: time.Hour, Deadman: time.Hour},
		AI:    ClassPolicy{TTL: time.Hour},
	}
	m := New(&fakeSpawner{}, motiongate.New(), &collectRecorder{}, nil, pol)

	l := mustAcquire(t, m, humanReq(1))
	if _, err := m.Check(l.ID, l.Conn); err != nil {
		t.Fatalf("Check: %v", err)
	}

	if n := testing.AllocsPerRun(200, func() { _, _ = m.Check(l.ID, l.Conn) }); n != 0 {
		t.Fatalf("Check allocated %v objects per run, want 0", n)
	}
	if n := testing.AllocsPerRun(200, func() { _ = m.Refresh(l.ID, l.Conn) }); n != 0 {
		t.Fatalf("Refresh allocated %v objects per run, want 0", n)
	}

	if n := testing.AllocsPerRun(200, func() { _, _ = m.Check(l.ID, ConnID(999)) }); n != 0 {
		t.Fatalf("rejected Check allocated %v objects per run, want 0", n)
	}
}

func TestRevokeAllIsAllocationFree(t *testing.T) {
	m, g, _ := newTestModule(t)

	if n := testing.AllocsPerRun(200, func() { m.RevokeAll(g.Epoch()) }); n != 0 {
		t.Fatalf("RevokeAll allocated %v objects per run, want 0", n)
	}
}
