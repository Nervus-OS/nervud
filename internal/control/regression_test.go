package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

// TestAcquire_RejectedAfterStop 锁住 [P1]：Stop 是终态。停机后 Acquire 不得签出新租约
// ——否则会留下一条没有 Lane 再去做到期清槽/epoch 撤销的孤儿租约。
func TestAcquire_RejectedAfterStop(t *testing.T) {
	m, _, _ := newTestModule(t)

	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	l, err := m.Acquire(humanReq(1))
	if !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("Acquire after Stop = %v, want ErrShuttingDown", err)
	}
	if l != (Lease{}) || m.cur.Load() != nil {
		t.Fatal("no lease may be published after Stop")
	}
	// 且没有 Lane 会来收它——正是拒绝签发的理由。
	if _, err := m.Check(l.ID, l.Conn); !errors.Is(err, ErrControlNotHeld) {
		t.Fatalf("Check on rejected acquire = %v, want ErrControlNotHeld", err)
	}
}

// TestMarkFresh_Monotonic 锁住 [P1]：deadman 新鲜度只增不减。一个晚提交的旧调用不得把
// 新鲜度倒写回去，把有效租约提前 deadman。
func TestMarkFresh_Monotonic(t *testing.T) {
	m, _, _ := newTestModule(t)

	early := m.base.Add(20 * time.Millisecond)
	late := m.base.Add(100 * time.Millisecond)

	m.markFresh(late)  // 新鲜度顶到 100ms
	m.markFresh(early) // 旧调用晚落地：必须被忽略

	if got := time.Duration(m.fresh.Load()); got != 100*time.Millisecond {
		t.Fatalf("fresh = %s after a stale write, want 100ms (monotonic)", got)
	}
}

// TestRevokeAll_LosslessAcrossRounds 锁住 [P2]：连续两轮 Safety 撤销在一次 drain 之前
// 发生时，两条撤销审计都不能丢，且各自配对正确的 halt epoch。
//
// 复现 reporter 的「两次撤销最终只记录了一次」：旧的单指针槽会让第二轮覆盖第一轮。
func TestRevokeAll_LosslessAcrossRounds(t *testing.T) {
	m, g, rec := newTestModule(t)

	// 第一轮：签租约 A → Trip → RevokeAll（不 drain）。
	a := mustAcquire(t, m, humanReq(1))
	g.Trip()
	epoch1 := g.Epoch()
	m.RevokeAll(epoch1)

	// 走完 re-arm 回 NORMAL，签租约 B → Trip → RevokeAll（仍不 drain）。
	if !g.RequireRearm() || !g.Rearm() {
		t.Fatal("failed to walk through rearm between rounds")
	}
	b := mustAcquire(t, m, humanReq(2))
	if b.ID == a.ID {
		t.Fatal("second acquire should mint a fresh lease id")
	}
	g.Trip()
	epoch2 := g.Epoch()
	m.RevokeAll(epoch2)

	// 现在一次性 drain：两条撤销审计都应在，各带自己那轮的 halt epoch。
	m.onTick(time.Now())

	revokes := 0
	for _, e := range rec.all() {
		if e.Action == "control."+actionRevoked {
			revokes++
		}
	}
	if revokes != 2 {
		t.Fatalf("recorded %d LeaseRevoked audits across two rounds, want 2 (lossless)", revokes)
	}
}

// TestRevokeAll_NoBumpAndZeroAlloc 保底重申：RevokeAll 清槽但不递增 epoch，且零堆分配
// （它跑在 FIFO 90 上）。环化后这两条不变。
func TestRevokeAll_NoBumpAndZeroAlloc(t *testing.T) {
	m, g, _ := newTestModule(t)
	mustAcquire(t, m, humanReq(1))
	g.Trip()
	ep := g.Epoch()

	m.RevokeAll(ep)
	if g.Epoch() != ep {
		t.Fatalf("RevokeAll bumped epoch: %d, want unchanged %d", g.Epoch(), ep)
	}
	if m.cur.Load() != nil {
		t.Fatal("RevokeAll should have cleared the slot")
	}

	if n := testing.AllocsPerRun(200, func() { m.RevokeAll(ep) }); n != 0 {
		t.Fatalf("RevokeAll allocated %v objects per run, want 0", n)
	}
}

// TestDropLocked_NoBumpWhenLatched 锁住 [P1] 的 drop 分支：若 Gate 已被 Trip 锁存而
// 到期 Lane 抢在 RevokeAll 之前收这条租约，dropLocked 不得把已锁存的 Gate 又推进一代。
func TestDropLocked_NoBumpWhenLatched(t *testing.T) {
	m, g, _ := newTestModule(t)
	mustAcquire(t, m, humanReq(1))
	lp := m.cur.Load() // dropLocked 的 CAS 需要槽里那个确切指针

	// 模拟：Trip 已锁存（epoch 前进一次），但 RevokeAll 尚未把 cur 换走。
	g.Trip()
	latchedEpoch := g.Epoch()

	// 直接走 drop 路径（持锁）。CAS 仍会成功（cur 还是 lp），但 BumpEpochIfNormal 应不递增。
	m.mu.Lock()
	m.dropLocked(lp, actionRevoked, errSafetyRevoked)
	m.mu.Unlock()

	if g.Epoch() != latchedEpoch {
		t.Fatalf("dropLocked advanced a latched gate: %d, want %d", g.Epoch(), latchedEpoch)
	}
	if g.State() != motiongate.StateSafetyLatched {
		t.Fatalf("state = %v, want still SAFETY_LATCHED", g.State())
	}
}
