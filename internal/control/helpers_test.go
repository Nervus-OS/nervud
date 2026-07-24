package control

import (
	"context"
	"sync"
	"testing"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/motiongate"
	"github.com/nervus-os/nervud/internal/scheduler"
)

type fakeSpawner struct {
	mu     sync.Mutex
	names  []string
	failOn map[string]error
	run    bool
	ctx    context.Context
}

func (s *fakeSpawner) SpawnDedicated(name string, _ scheduler.Policy, _ int, fn func(context.Context)) error {
	s.mu.Lock()
	s.names = append(s.names, name)
	err := s.failOn[name]
	run := s.run
	ctx := s.ctx
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if run {
		if ctx == nil {
			ctx = context.Background()
		}
		go fn(ctx)
	}
	return nil
}

func (s *fakeSpawner) laneNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.names))
	copy(out, s.names)
	return out
}

type collectRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *collectRecorder) Record(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *collectRecorder) all() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

func (r *collectRecorder) actions() []string {
	evs := r.all()
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Action)
	}
	return out
}

func (r *collectRecorder) has(action string) bool {
	for _, a := range r.actions() {
		if a == "control."+action {
			return true
		}
	}
	return false
}

func newTestModule(t *testing.T) (*Module, *motiongate.Gate, *collectRecorder) {
	t.Helper()
	g := motiongate.New()
	rec := &collectRecorder{}
	return New(&fakeSpawner{}, g, rec, nil, DefaultPolicy()), g, rec
}

func testCaller(pkg string, uid uint32) identity.Caller {
	return identity.Caller{PackageID: pkg, UID: uid, Trust: identity.TrustOrdinary}
}

func humanReq(conn ConnID) Request {
	return Request{
		Conn: conn, Class: ClassHuman, Resource: ResourceBaseMain,
		Owner: testCaller("com.example.teleop", 20001),
	}
}

func aiReq(conn ConnID) Request {
	return Request{
		Conn: conn, Class: ClassAI, Resource: ResourceBaseMain,
		Owner: testCaller("os.nervus.agent", 20002),
	}
}

func mustAcquire(t *testing.T, m *Module, req Request) Lease {
	t.Helper()
	l, err := m.Acquire(req)
	if err != nil {
		t.Fatalf("Acquire(%s): %v", req.Class, err)
	}
	return l
}
