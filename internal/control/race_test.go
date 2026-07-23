package control

import (
	"sync"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

// TestConcurrentLifecycle 让全部路径同时跑，交给 -race 与死锁检测
//
// 本用例不断言业务结论——并发下任何「读完再断言」的写法本身就是竞态。它要抓的是两类
// 结构性问题：① 数据竞争（尤其 RevokeAll 不取 mu、与持锁路径交错这一处设计）；
// ② 死锁（Lane 的 onTick 与控制面路径对 mu 的取用顺序）
//
// 逻辑正确性由 TestEpochLedger 等确定性用例保证
func TestConcurrentLifecycle(t *testing.T) {
	m, g, _ := newTestModule(t)

	const rounds = 300
	var wg sync.WaitGroup

	// 控制面：反复签发/续租/释放
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			l, err := m.Acquire(humanReq(1))
			if err != nil {
				continue // 被 latch 或被抢占，正常
			}
			_, _ = m.Renew(l.ID, l.Conn)
			_, _ = m.Check(l.ID, l.Conn)
			_ = m.Refresh(l.ID, l.Conn)
			_ = m.Release(l.ID, l.Conn)
		}
	}()

	// 另一个控制主体：AI 反复来抢（大多会被拒）
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if l, err := m.Acquire(aiReq(2)); err == nil {
				_ = m.Release(l.ID, l.Conn)
			}
		}
	}()

	// 连接断开
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			m.RevokeConn(1)
		}
	}()

	// Safety：触发 → 撤销 → 走完 re-arm 回到 NORMAL
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds/10; i++ {
			g.Trip()
			m.RevokeAll(g.Epoch()) // 模拟 Supervisor Lane（FIFO 90）的同步调用
			g.RequireRearm()
			g.Rearm()
		}
	}()

	// Control Lane 的到期检测
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			m.onTick(time.Now())
		}
	}()

	wg.Wait()

	// 静默之后做一次一致性收束：先把 Gate 拨回 NORMAL（它可能停在 latch/rearm 的
	// 任一相），再让 Lane 跑一拍，然后要求槽里要么是空的、要么是一条仍然自洽的租约
	for i := 0; i < 4 && g.State() != motiongate.StateNormal; i++ {
		g.RequireRearm()
		g.Rearm()
	}
	m.onTick(time.Now())

	if g.State() != motiongate.StateNormal {
		t.Fatalf("gate stuck at %v after rearm attempts", g.State())
	}
	if l := m.cur.Load(); l != nil {
		if _, err := m.Check(l.ID, l.Conn); err != nil {
			t.Fatalf("lease left in the slot is not self-consistent: %v", err)
		}
	}
}
