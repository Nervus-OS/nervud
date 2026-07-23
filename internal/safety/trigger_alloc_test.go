package safety

import "testing"

// TestTrip_AllocFree 守住 Safety 触发热路径的零堆分配硬规则（架构 §6 item6；
// README §质量门禁 item5）。Trip = gate.Trip + 原子 store + 两次非阻塞 wake。
func TestTrip_AllocFree(t *testing.T) {
	m := newTestModule()
	if n := testing.AllocsPerRun(1000, func() { m.Trip(ReasonOperatorEStop) }); n != 0 {
		t.Fatalf("Trip allocs/op = %v, want 0", n)
	}
}

// TestDeliverHalt_AllocFree 守住 Stop Lane 投递路径的零堆分配：
// gate.Epoch + 原子 load + NopPath.SendHalt + ring.push，全程无分配。
func TestDeliverHalt_AllocFree(t *testing.T) {
	m := newTestModule()
	if n := testing.AllocsPerRun(1000, func() { m.deliverHalt() }); n != 0 {
		t.Fatalf("deliverHalt allocs/op = %v, want 0", n)
	}
}
