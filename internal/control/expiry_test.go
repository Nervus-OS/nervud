package control

import (
	"errors"
	"testing"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

// TestExpiryReasons 到期与 deadman 失效必须记成【不同】的审计 Action
//
// 两者的产品含义完全不同：一个是「时限正常到了」，一个是「人或链路失联了」。
// 混成一条，离线分析就再也分不出「遥控链路在抖」这种真正需要关注的信号
func TestExpiryReasons(t *testing.T) {
	tests := []struct {
		name       string
		req        Request
		at         func(l Lease) time.Time
		wantAction string
	}{
		{
			name:       "deadline 到期",
			req:        func() Request { r := aiReq(1); r.TTL = 50 * time.Millisecond; return r }(),
			at:         func(l Lease) time.Time { return l.Deadline.Add(time.Millisecond) },
			wantAction: actionExpired,
		},
		{
			name:       "deadman 失效",
			req:        humanReq(1),
			at:         func(l Lease) time.Time { return l.IssuedAt.Add(400 * time.Millisecond) },
			wantAction: actionDeadmanExpired,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, rec := newTestModule(t)
			l := mustAcquire(t, m, tc.req)

			m.onTick(tc.at(l))

			if m.cur.Load() != nil {
				t.Fatal("expired lease should have been collected by the lane")
			}
			if !rec.has(tc.wantAction) {
				t.Fatalf("expected control.%s, got %v", tc.wantAction, rec.actions())
			}
			if _, err := m.Check(l.ID, l.Conn); !errors.Is(err, ErrControlNotHeld) {
				t.Fatalf("Check after expiry = %v, want ErrControlNotHeld", err)
			}
		})
	}
}

// TestRefreshKeepsDeadmanAlive 持续的新鲜输入让 deadman 一直不触发
func TestRefreshKeepsDeadmanAlive(t *testing.T) {
	m, _, _ := newTestModule(t)
	l := mustAcquire(t, m, humanReq(1))

	// deadman 300ms：每 100ms 刷新一次，走满 900ms 也不该掉
	for i := 1; i <= 9; i++ {
		at := l.IssuedAt.Add(time.Duration(i) * 100 * time.Millisecond)
		m.markFresh(at)
		m.onTick(at)
		if m.cur.Load() == nil {
			t.Fatalf("lease dropped at %dms despite fresh input", i*100)
		}
	}

	// 停止刷新后 300ms 内必须掉
	m.onTick(l.IssuedAt.Add(1300 * time.Millisecond))
	if m.cur.Load() != nil {
		t.Fatal("lease survived a deadman window with no fresh input")
	}
}

// TestLaneIgnoresSafetyOwnedBoundaries Safety 已锁存时，Lane 不得抢着收租约
//
// 那条边界的 epoch 由 gate.Trip 递增过、租约由 RevokeAll 收走。Lane 若也动手，
// 就会多递增一次 epoch 并记出重复审计
func TestLaneIgnoresSafetyOwnedBoundaries(t *testing.T) {
	m, g, _ := newTestModule(t)
	mustAcquire(t, m, humanReq(1))

	g.Trip()
	epochAfterTrip := g.Epoch()

	// 此刻租约还在槽里（RevokeAll 尚未被调用），且已经因锁存而失效
	m.onTick(time.Now().Add(time.Hour))

	if g.Epoch() != epochAfterTrip {
		t.Fatalf("lane bumped epoch on a safety-owned boundary: %d -> %d", epochAfterTrip, g.Epoch())
	}
	if m.cur.Load() == nil {
		t.Fatal("lane collected a lease that belongs to safety's revoke path")
	}
}

// TestControlSnapshot 有效控制来源的判定顺序（Agent 文档 §3.3）
func TestControlSnapshot(t *testing.T) {
	m, g, _ := newTestModule(t)

	if s := m.ControlSnapshot(); s.Source != SourceNone || s.Held {
		t.Fatalf("fresh module = %+v, want NONE", s)
	}

	l := mustAcquire(t, m, aiReq(1))
	s := m.ControlSnapshot()
	if s.Source != SourceAI || !s.Held || s.Lease.ID != l.ID {
		t.Fatalf("after AI acquire = %+v, want AI", s)
	}

	mustAcquire(t, m, humanReq(2))
	if s := m.ControlSnapshot(); s.Source != SourceHuman {
		t.Fatalf("after HUMAN preempt = %+v, want HUMAN", s)
	}

	// Safety 压过一切：即便槽里还残留着租约，来源也必须是 SAFETY
	g.Trip()
	s = m.ControlSnapshot()
	if s.Source != SourceSafety {
		t.Fatalf("after trip = %+v, want SAFETY", s)
	}
	if s.State != motiongate.StateSafetyLatched {
		t.Fatalf("snapshot state = %v, want SAFETY_LATCHED", s.State)
	}
}
