package safety

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

func moduleWith(sp *fakeSpawner, c Contract) *Module {
	return New(sp, motiongate.New(), &collectRecorder{}, nil, c, NopPath(), NopReports(), nil)
}

func TestStart_SpawnsTwoLanesThenStops(t *testing.T) {
	sp := &fakeSpawner{}
	m := moduleWith(sp, DefaultContract())

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	names := sp.laneNames()
	if len(names) != 2 || names[0] != "safety-stop" || names[1] != "safety-supervisor" {
		t.Fatalf("lanes = %v, want [safety-stop safety-supervisor]", names)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestStart_InvalidContractFailsFast(t *testing.T) {
	m := moduleWith(&fakeSpawner{}, Contract{}) // 全零 = 非法
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("Start with invalid contract should fail")
	}
}

func TestStart_LaneSpawnErrorFailsFast(t *testing.T) {
	sp := &fakeSpawner{failOn: map[string]error{"safety-supervisor": errors.New("boom")}}
	m := moduleWith(sp, DefaultContract())
	err := m.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Start err = %v, want to wrap 'boom'", err)
	}
}

func TestLane_UnexpectedExitReportsFatal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sp := &fakeSpawner{run: true, ctx: ctx}
	m := moduleWith(sp, DefaultContract())
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// 模拟「关闭序被打乱」：sched ctx 在模块 Stop 之前被取消 → lane 经 ctx 退出。
	cancel()

	select {
	case err := <-m.Fatal():
		if err == nil {
			t.Fatal("Fatal reported nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a Fatal report after unexpected lane exit")
	}
	_ = m.Stop(context.Background()) // 收尾，让 auditDrain 退出
}

func TestStop_CleanExitNoFatal(t *testing.T) {
	sp := &fakeSpawner{run: true, ctx: context.Background()} // ctx 永不取消
	m := moduleWith(sp, DefaultContract())
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// 给 lane goroutine 经 stopCh 退出的时间；laneFn 不应上报 Fatal。
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-m.Fatal():
		t.Fatalf("unexpected Fatal on clean stop: %v", err)
	default:
	}
}

func TestAuditDrain_RecordsHaltDelivered(t *testing.T) {
	rec := &collectRecorder{}
	m := New(&fakeSpawner{}, motiongate.New(), rec, nil,
		DefaultContract(), NopPath(), NopReports(), nil)

	// 不起真实 Lane：直接跑一次投递，再手动排空一次（模拟 auditDrain 的一次轮询）。
	m.deliverHalt()
	m.drainAll()

	found := false
	for _, e := range rec.all() {
		if e.Action == "safety.halt_delivered" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a safety.halt_delivered audit event, got %+v", rec.all())
	}
}

func TestObserverAndController(t *testing.T) {
	m := newTestModule()

	if snap := m.SafetySnapshot(); snap.State != motiongate.StateNormal || snap.Epoch != 1 {
		t.Fatalf("initial snapshot = %+v, want NORMAL/epoch 1", snap)
	}

	// RequestStop 同步锁存（不依赖任何 Lane 运行）。
	m.RequestStop(ReasonOperatorEStop)

	snap := m.SafetySnapshot()
	if snap.State != motiongate.StateSafetyLatched || snap.Epoch != 2 {
		t.Fatalf("after RequestStop snapshot = %+v, want SAFETY_LATCHED/epoch 2", snap)
	}
}

// TestRearmRequiresSettledStopProgress 内核在 re-arm 上只守一条硬前置：停止进度必须
// 已经落定。停止还在途中就解开 latch，等于在还不知道输出有没有关掉的情况下重新放行运动
func TestRearmRequiresSettledStopProgress(t *testing.T) {
	tests := []struct {
		phase StopPhase
		allow bool
	}{
		{phase: PhaseUnspecified},      // Supervisor 还没开始跟踪
		{phase: PhaseRequested},        // 刚锁存，停止帧还没发
		{phase: PhaseSent},             // 发了，没人确认
		{phase: PhaseProviderAccepted}, // Provider 收了，设备未必停
		{phase: PhaseMCUAcked},         // MCU 收了，输出未必关
		{phase: PhaseOutputDisabled, allow: true},
		{phase: PhaseStandstillConfirmed, allow: true},
		{phase: PhaseDeliveryFault, allow: true},     // 终态：已经必须人工处置
		{phase: PhaseStandstillTimeout, allow: true}, // 同上，不能永久锁死设备
	}

	for _, tc := range tests {
		t.Run(tc.phase.String(), func(t *testing.T) {
			rec := &collectRecorder{}
			m := New(&fakeSpawner{}, motiongate.New(), rec, nil,
				DefaultContract(), NopPath(), NopReports(), nil)

			m.Trip(ReasonOperatorEStop)
			if !m.gate.RequireRearm() {
				t.Fatal("RequireRearm should succeed from SAFETY_LATCHED")
			}
			// 相位必须绑定到当前这一轮的 halt epoch，否则 Rearm 会因 epoch 不符而拒绝
			m.phase.Store(packPhase(tc.phase, m.gate.Epoch()))

			if got := m.Rearm(); got != tc.allow {
				t.Fatalf("Rearm() = %v, want %v (phase %s)", got, tc.allow, tc.phase)
			}

			wantState := motiongate.StateRearmRequired
			if tc.allow {
				wantState = motiongate.StateNormal
			}
			if got := m.gate.State(); got != wantState {
				t.Fatalf("state = %v, want %v", got, wantState)
			}

			if !tc.allow {
				found := false
				for _, e := range rec.all() {
					if e.Action == "safety.rearm_rejected" {
						found = true
					}
				}
				if !found {
					t.Fatal("a refused re-arm must leave an audit record")
				}
			}
		})
	}
}
