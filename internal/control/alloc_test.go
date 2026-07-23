package control

import (
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

// TestCheckAndRefreshAreAllocationFree 派发前复核必须零堆分配
//
// Check/Refresh 在【每条运动命令】上被调用。它们要是分配，控制回路的每一拍都会给 GC
// 添一份垃圾——这与 Safety Stop Lane 的零分配硬规则不是同一条（那条针对急停投递），
// 但同样进 CI 守住。真正的约束来源：这两个函数只读原子量，返回的错误全是预分配哨兵
func TestCheckAndRefreshAreAllocationFree(t *testing.T) {
	// 用一个 TTL 很长的 Policy，避免慢机器上租约在测量循环中途到期
	// （到期后走的是另一条分支，测的就不是这里想测的路径了）
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

	// 失败路径同样零分配：被拒的调用可以由一个刷命令的 App 任意制造，
	// 那条路径分配就等于把拒绝变成了一个 GC 压力放大器
	if n := testing.AllocsPerRun(200, func() { _, _ = m.Check(l.ID, ConnID(999)) }); n != 0 {
		t.Fatalf("rejected Check allocated %v objects per run, want 0", n)
	}
}

// TestRevokeAllIsAllocationFree RevokeAll 跑在 Safety Supervisor Lane（FIFO 90）上，
// 由 safety 在锁存后同步调用。它只做原子操作，不取锁、不分配、不落审计
func TestRevokeAllIsAllocationFree(t *testing.T) {
	m, g, _ := newTestModule(t)

	if n := testing.AllocsPerRun(200, func() { m.RevokeAll(g.Epoch()) }); n != 0 {
		t.Fatalf("RevokeAll allocated %v objects per run, want 0", n)
	}
}
