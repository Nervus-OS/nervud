package health

import (
	"context"
	"testing"

	"github.com/nervus-os/nervud/internal/control"
	"github.com/nervus-os/nervud/internal/motiongate"
	"github.com/nervus-os/nervud/internal/safety"
	"github.com/nervus-os/nervud/internal/service"
)

// ---- 测试替身（同 internal/endpoint 的 fakePkgs/fakePerm/fakeStarter 风格）----

type fakeSafetyObserver struct {
	snap safety.Snapshot
}

func (f fakeSafetyObserver) SafetySnapshot() safety.Snapshot { return f.snap }

type fakeControlObserver struct {
	snap control.Snapshot
}

func (f fakeControlObserver) ControlSnapshot() control.Snapshot { return f.snap }

type fakeServiceObserver struct {
	instances []service.Instance
}

func (f fakeServiceObserver) Instances() []service.Instance { return f.instances }

func normalSafety() safety.Snapshot {
	return safety.Snapshot{State: motiongate.StateNormal, Epoch: 1}
}

// ---- deriveStatus 三档规则 ----

func TestDeriveStatus_HealthyWhenNormalAndNoFailedComponents(t *testing.T) {
	comps := []service.Instance{{State: service.StateRunning}, {State: service.StateStopped}}
	if got := deriveStatus(normalSafety(), comps); got != StatusHealthy {
		t.Fatalf("deriveStatus = %v, want Healthy", got)
	}
}

func TestDeriveStatus_DegradedWhenNormalWithFailedComponent(t *testing.T) {
	comps := []service.Instance{{State: service.StateRunning}, {State: service.StateFailed}}
	if got := deriveStatus(normalSafety(), comps); got != StatusDegraded {
		t.Fatalf("deriveStatus = %v, want Degraded", got)
	}
}

func TestDeriveStatus_FaultWhenSafetyNotNormal(t *testing.T) {
	states := []motiongate.State{
		motiongate.StateInvalid,
		motiongate.StateSafetyLatched,
		motiongate.StateOEMRecovery,
		motiongate.StateRearmRequired,
	}
	for _, s := range states {
		snap := safety.Snapshot{State: s}
		if got := deriveStatus(snap, nil); got != StatusFault {
			t.Fatalf("deriveStatus(State=%v) = %v, want Fault", s, got)
		}
	}
}

// TestDeriveStatus_FaultOutranksDegraded 锁住"Safety 优先于组件熔断"这个前提：
// 即使同时存在 StateFailed 组件，只要 Safety 不是 NORMAL 就必须报 Fault，
// 不能被组件级信号盖过
func TestDeriveStatus_FaultOutranksDegraded(t *testing.T) {
	comps := []service.Instance{{State: service.StateFailed}}
	snap := safety.Snapshot{State: motiongate.StateSafetyLatched}
	if got := deriveStatus(snap, comps); got != StatusFault {
		t.Fatalf("deriveStatus = %v, want Fault (Safety must outrank Degraded)", got)
	}
}

// TestDeriveStatus_NonFailedStatesIgnored 锁住"只有 StateFailed 才计入 Degraded"：
// 其余组件状态不应被误判为 Degraded
func TestDeriveStatus_NonFailedStatesIgnored(t *testing.T) {
	comps := []service.Instance{
		{State: service.StateStopped},
		{State: service.StateStarting},
		{State: service.StateRunning},
		{State: service.StateStopping},
		{State: service.StateDisabled},
	}
	if got := deriveStatus(normalSafety(), comps); got != StatusHealthy {
		t.Fatalf("deriveStatus = %v, want Healthy (non-Failed states must not count)", got)
	}
}

// ---- nil Observer / nil Module fail-closed ----

func TestReport_NilObserversFailClosed(t *testing.T) {
	m := New(nil, nil, nil)
	r := m.Report()
	if r.Status != StatusFault {
		t.Fatalf("Report().Status = %v, want Fault when all observers are nil", r.Status)
	}
}

func TestReport_PartialNilObserverStillFailsClosed(t *testing.T) {
	// safety 缺失，即使 control/service 都装配好了，也不能被误判成 Healthy
	m := New(nil, fakeControlObserver{}, fakeServiceObserver{})
	r := m.Report()
	if r.Status != StatusFault {
		t.Fatalf("Report().Status = %v, want Fault when safety observer is nil", r.Status)
	}
}

func TestReport_NilModuleFailSafe(t *testing.T) {
	var m *Module
	r := m.Report()
	if r.Status != StatusFault {
		t.Fatalf("(*Module)(nil).Report().Status = %v, want Fault", r.Status)
	}
}

// ---- 聚合正确性：原样透传，未被二次改写 ----

func TestReport_AggregatesWithoutRewriting(t *testing.T) {
	wantSafety := safety.Snapshot{State: motiongate.StateNormal, Epoch: 7, StopPhase: safety.PhaseUnspecified}
	wantControl := control.Snapshot{State: motiongate.StateNormal, Epoch: 7, Held: true}
	wantComps := []service.Instance{
		{PackageID: "pkg.a", ComponentID: "comp.a", State: service.StateRunning},
		{PackageID: "pkg.b", ComponentID: "comp.b", State: service.StateFailed},
	}

	m := New(fakeSafetyObserver{wantSafety}, fakeControlObserver{wantControl}, fakeServiceObserver{wantComps})
	r := m.Report()

	if r.Safety != wantSafety {
		t.Fatalf("Report().Safety = %+v, want %+v", r.Safety, wantSafety)
	}
	if r.Control != wantControl {
		t.Fatalf("Report().Control = %+v, want %+v", r.Control, wantControl)
	}
	// service.Instance 含未导出的 slice/channel 字段（crashes/stopCh/done），
	// 不可比较，因此只断言透传到 Report 的可见状态未被二次改写
	if len(r.Components) != len(wantComps) {
		t.Fatalf("Report().Components = %+v, want %+v", r.Components, wantComps)
	}
	for i := range wantComps {
		if r.Components[i].PackageID != wantComps[i].PackageID ||
			r.Components[i].ComponentID != wantComps[i].ComponentID ||
			r.Components[i].State != wantComps[i].State {
			t.Fatalf("Report().Components[%d] = %+v, want %+v", i, &r.Components[i], &wantComps[i])
		}
	}
	if r.Status != StatusDegraded {
		t.Fatalf("Report().Status = %v, want Degraded", r.Status)
	}
}

// ---- Status.String ----

func TestStatusString(t *testing.T) {
	cases := map[Status]string{
		StatusHealthy:  "HEALTHY",
		StatusDegraded: "DEGRADED",
		StatusFault:    "FAULT",
	}
	for status, want := range cases {
		if got := status.String(); got != want {
			t.Fatalf("Status(%d).String() = %q, want %q", status, got, want)
		}
	}
}

// ---- Module 生命周期 ----

func TestModuleLifecycle(t *testing.T) {
	m := New(fakeSafetyObserver{normalSafety()}, fakeControlObserver{}, fakeServiceObserver{})
	if got := m.Name(); got != "health" {
		t.Fatalf("Name() = %q, want %q", got, "health")
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() = %v, want nil", err)
	}
}
