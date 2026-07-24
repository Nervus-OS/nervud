package safety

import (
	"context"
	"sync"

	"github.com/nervus-os/nervud/internal/audit"
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

func newTestModule() *Module {
	return New(&fakeSpawner{}, motiongate.New(), &collectRecorder{}, nil,
		DefaultContract(), NopPath(), NopReports(), nil)
}

func contractSupportingStandstill() Contract {
	c := DefaultContract()
	c.StandstillConfirmationSupported = true
	return c
}

func drainKinds(r *auditRing) []eventKind {
	var out []eventKind
	for {
		rec, ok := r.pop()
		if !ok {
			return out
		}
		out = append(out, rec.kind)
	}
}

func containsKind(ks []eventKind, want eventKind) bool {
	for _, k := range ks {
		if k == want {
			return true
		}
	}
	return false
}
