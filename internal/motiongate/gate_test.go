package motiongate

import (
	"sync"
	"testing"
)

func TestNew_NormalNonZeroEpoch(t *testing.T) {
	g := New()
	s, e := g.Snapshot()
	if s != StateNormal {
		t.Fatalf("New state = %v, want NORMAL", s)
	}
	if e != 1 {
		t.Fatalf("New epoch = %d, want 1 (epoch must be non-zero)", e)
	}
}

func TestZeroValue_FailClosed(t *testing.T) {
	// 零值 Gate 未经 New()：必须解出 (Invalid, 0)，双重 fail-closed。
	var g Gate
	s, e := g.Snapshot()
	if s != StateInvalid {
		t.Fatalf("zero-value state = %v, want INVALID", s)
	}
	if e != 0 {
		t.Fatalf("zero-value epoch = %d, want 0 (invalid generation)", e)
	}
}

func TestPackRoundTrip(t *testing.T) {
	// 边界 epoch 也要能无损打包/解包，且 State 位不污染 epoch 位。
	for _, e := range []uint64{0, 1, 2, epochMask - 1, epochMask} {
		for _, st := range []State{StateNormal, StateSafetyLatched, StateOEMRecovery, StateRearmRequired} {
			gs, ge := unpack(pack(st, e))
			if gs != st || ge != e {
				t.Fatalf("roundtrip (%v,%d) -> (%v,%d)", st, e, gs, ge)
			}
		}
	}
}

func TestTrip_LatchesAndBumpsOnce(t *testing.T) {
	g := New() // (Normal, 1)

	if !g.Trip() {
		t.Fatal("first Trip should report a transition")
	}
	if s, e := g.Snapshot(); s != StateSafetyLatched || e != 2 {
		t.Fatalf("after Trip = (%v,%d), want (SAFETY_LATCHED,2)", s, e)
	}

	// 幂等：已锁存再 Trip 不改状态、不 churn epoch，返回 false。
	if g.Trip() {
		t.Fatal("second Trip should be a no-op (false)")
	}
	if s, e := g.Snapshot(); s != StateSafetyLatched || e != 2 {
		t.Fatalf("after redundant Trip = (%v,%d), want (SAFETY_LATCHED,2)", s, e)
	}
}

func TestBumpEpoch_PreservesState(t *testing.T) {
	g := New()
	g.BumpEpoch()
	if s, e := g.Snapshot(); s != StateNormal || e != 2 {
		t.Fatalf("after BumpEpoch(Normal) = (%v,%d), want (NORMAL,2)", s, e)
	}
	g.Trip() // (Latched, 3)
	g.BumpEpoch()
	if s, e := g.Snapshot(); s != StateSafetyLatched || e != 4 {
		t.Fatalf("after BumpEpoch(Latched) = (%v,%d), want (SAFETY_LATCHED,4)", s, e)
	}
}

func TestRecoveryRearmCycle(t *testing.T) {
	g := New() // (Normal, 1)

	// 未锁存时不能进恢复/复位。
	if g.BeginRecovery() || g.RequireRearm() || g.Rearm() {
		t.Fatal("recovery/rearm transitions must fail from NORMAL")
	}

	g.Trip() // (Latched, 2)

	if !g.BeginRecovery() { // (OEMRecovery, 2)
		t.Fatal("BeginRecovery should succeed from SAFETY_LATCHED")
	}
	if s, e := g.Snapshot(); s != StateOEMRecovery || e != 2 {
		t.Fatalf("after BeginRecovery = (%v,%d), want (OEM_RECOVERY,2)", s, e)
	}

	if !g.RequireRearm() { // (RearmRequired, 2)
		t.Fatal("RequireRearm should succeed from OEM_RECOVERY")
	}
	if s, e := g.Snapshot(); s != StateRearmRequired || e != 2 {
		t.Fatalf("after RequireRearm = (%v,%d), want (REARM_REQUIRED,2)", s, e)
	}

	if !g.Rearm() { // (Normal, 3) —— re-arm 递增 epoch
		t.Fatal("Rearm should succeed from REARM_REQUIRED")
	}
	if s, e := g.Snapshot(); s != StateNormal || e != 3 {
		t.Fatalf("after Rearm = (%v,%d), want (NORMAL,3): re-arm must bump epoch", s, e)
	}
}

func TestRequireRearm_FromLatchedDirectly(t *testing.T) {
	// 允许跳过 OEM_RECOVERY 直接从 SAFETY_LATCHED 要求 re-arm。
	g := New()
	g.Trip() // (Latched, 2)
	if !g.RequireRearm() {
		t.Fatal("RequireRearm should succeed directly from SAFETY_LATCHED")
	}
	if s, _ := g.Snapshot(); s != StateRearmRequired {
		t.Fatalf("state = %v, want REARM_REQUIRED", s)
	}
}

func TestTrip_DuringRecovery_RelatchesAndBumps(t *testing.T) {
	// 恢复阶段来了新的 Safety 触发：必须重新 latch 并递增 epoch，废止恢复残留命令。
	g := New()
	g.Trip()          // (Latched, 2)
	g.BeginRecovery() // (OEMRecovery, 2)

	if !g.Trip() {
		t.Fatal("Trip during OEM_RECOVERY should report a transition")
	}
	if s, e := g.Snapshot(); s != StateSafetyLatched || e != 3 {
		t.Fatalf("after re-trip = (%v,%d), want (SAFETY_LATCHED,3)", s, e)
	}
}

func TestIncEpoch_SkipsZeroOnWrap(t *testing.T) {
	// 回绕（现实中不可达）也必须跳过 0，维持 epoch 恒非零。
	if got := incEpoch(epochMask); got != 1 {
		t.Fatalf("incEpoch(max) = %d, want 1 (skip 0 on wrap)", got)
	}
	if got := incEpoch(1); got != 2 {
		t.Fatalf("incEpoch(1) = %d, want 2", got)
	}
}

func TestConcurrent_NoTornReadEpochMonotonic(t *testing.T) {
	// 并发 Trip/BumpEpoch 下：读者永不看到 Invalid 态或 epoch 倒退（撕裂读）。
	// 配合 `go test -race` 一起跑最有价值。
	g := New()

	const writers = 8
	const iters = 20000

	stop := make(chan struct{})
	readerErr := make(chan string, 1)

	// 读者：全程监视一致性，直到 stop 关闭。
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		var last uint64
		for {
			select {
			case <-stop:
				return
			default:
			}
			s, e := g.Snapshot()
			if s == StateInvalid {
				select {
				case readerErr <- "observed StateInvalid on a live Gate":
				default:
				}
				return
			}
			if e < last {
				select {
				case readerErr <- "epoch went backwards (torn read?)":
				default:
				}
				return
			}
			last = e
		}
	}()

	// 写者：一半 BumpEpoch、一半 Trip。
	var writersWG sync.WaitGroup
	for w := 0; w < writers; w++ {
		writersWG.Add(1)
		go func(id int) {
			defer writersWG.Done()
			for i := 0; i < iters; i++ {
				if (id+i)%2 == 0 {
					g.BumpEpoch()
				} else {
					g.Trip()
				}
			}
		}(w)
	}

	writersWG.Wait() // 写者全部跑完
	close(stop)      // 再停读者
	readerWG.Wait()

	select {
	case msg := <-readerErr:
		t.Fatal(msg)
	default:
	}

	// 至少发生过若干次递增（BumpEpoch 一定推进）。
	if e := g.Epoch(); e < 2 {
		t.Fatalf("final epoch = %d, expected many increments", e)
	}
}

func TestAllocFree_HotPaths(t *testing.T) {
	g := New()
	if n := testing.AllocsPerRun(1000, func() { g.Trip() }); n != 0 {
		t.Fatalf("Trip allocs/op = %v, want 0", n)
	}
	if n := testing.AllocsPerRun(1000, func() { g.BumpEpoch() }); n != 0 {
		t.Fatalf("BumpEpoch allocs/op = %v, want 0", n)
	}
	if n := testing.AllocsPerRun(1000, func() { _, _ = g.Snapshot() }); n != 0 {
		t.Fatalf("Snapshot allocs/op = %v, want 0", n)
	}
}
