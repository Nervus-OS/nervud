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

func TestBumpEpochIfNormal(t *testing.T) {
	g := New() // (Normal, 1)

	if ne, ok := g.BumpEpochIfNormal(); !ok || ne != 2 {
		t.Fatalf("BumpEpochIfNormal(Normal) = (%d,%v), want (2,true)", ne, ok)
	}
	if s, e := g.Snapshot(); s != StateNormal || e != 2 {
		t.Fatalf("after = (%v,%d), want (NORMAL,2)", s, e)
	}

	g.Trip() // (Latched, 3)
	if ne, ok := g.BumpEpochIfNormal(); ok || ne != 3 {
		t.Fatalf("BumpEpochIfNormal(Latched) = (%d,%v), want (3,false)", ne, ok)
	}
	if s, e := g.Snapshot(); s != StateSafetyLatched || e != 3 {
		t.Fatalf("latched epoch must not advance: (%v,%d), want (SAFETY_LATCHED,3)", s, e)
	}

	g.RequireRearm() // (RearmRequired, 3)
	if _, ok := g.BumpEpochIfNormal(); ok {
		t.Fatal("BumpEpochIfNormal must fail in REARM_REQUIRED")
	}
	if _, e := g.Snapshot(); e != 3 {
		t.Fatalf("epoch advanced in REARM_REQUIRED: %d, want 3", e)
	}
}

func TestBumpEpochIfNormal_ZeroAlloc(t *testing.T) {
	g := New()
	if n := testing.AllocsPerRun(200, func() { g.BumpEpochIfNormal() }); n != 0 {
		t.Fatalf("BumpEpochIfNormal allocated %v objects per run, want 0", n)
	}
}

func TestRecoveryRearmCycle(t *testing.T) {
	g := New() // (Normal, 1)

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

	if !g.Rearm() {
		t.Fatal("Rearm should succeed from REARM_REQUIRED")
	}
	if s, e := g.Snapshot(); s != StateNormal || e != 3 {
		t.Fatalf("after Rearm = (%v,%d), want (NORMAL,3): re-arm must bump epoch", s, e)
	}
}

func TestRequireRearm_FromLatchedDirectly(t *testing.T) {
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
	if got := incEpoch(epochMask); got != 1 {
		t.Fatalf("incEpoch(max) = %d, want 1 (skip 0 on wrap)", got)
	}
	if got := incEpoch(1); got != 2 {
		t.Fatalf("incEpoch(1) = %d, want 2", got)
	}
}

func TestConcurrent_NoTornReadEpochMonotonic(t *testing.T) {
	g := New()

	const writers = 8
	const iters = 20000

	stop := make(chan struct{})
	readerErr := make(chan string, 1)

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

	writersWG.Wait()
	close(stop)
	readerWG.Wait()

	select {
	case msg := <-readerErr:
		t.Fatal(msg)
	default:
	}

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
