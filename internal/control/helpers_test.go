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

// fakeSpawner 是 LaneSpawner 的测试替身（与 internal/safety 的同名替身同一形状）：
// 记录被起的 lane 名，可按名注入失败，run=true 时用 ctx 真正跑 fn
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

// collectRecorder 收集审计事件，供断言
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

// actions 返回已记录的 Action 序列，供顺序断言
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

// newTestModule 构造一个不起真实 Lane 的 Module，并返回与之共享的 Gate 与审计收集器
func newTestModule(t *testing.T) (*Module, *motiongate.Gate, *collectRecorder) {
	t.Helper()
	g := motiongate.New()
	rec := &collectRecorder{}
	return New(&fakeSpawner{}, g, rec, nil, DefaultPolicy()), g, rec
}

func testCaller(pkg string, uid uint32) identity.Caller {
	return identity.Caller{PackageID: pkg, UID: uid, Trust: identity.TrustOrdinary}
}

// humanReq / aiReq 是两类申请的最小合法形态（TTL/deadman 取 Policy 默认）
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
