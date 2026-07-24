package safety

import "testing"

func TestTrip_AllocFree(t *testing.T) {
	m := newTestModule()
	if n := testing.AllocsPerRun(1000, func() { m.Trip(ReasonOperatorEStop) }); n != 0 {
		t.Fatalf("Trip allocs/op = %v, want 0", n)
	}
}

func TestDeliverHalt_AllocFree(t *testing.T) {
	m := newTestModule()
	if n := testing.AllocsPerRun(1000, func() { m.deliverHalt() }); n != 0 {
		t.Fatalf("deliverHalt allocs/op = %v, want 0", n)
	}
}
