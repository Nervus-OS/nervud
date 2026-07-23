package control

import (
	"errors"
	"testing"
	"time"
)

// epochProbe 测量一段动作产生的 epoch 增量
//
// reset 让用例把「准备动作」（比如先签一条 AI 租约好让 HUMAN 去抢）的递增排除在
// 断言之外，只测真正关心的那一个边界
type epochProbe struct {
	m    *Module
	base uint64
}

func (p *epochProbe) reset()        { p.base = p.m.gate.Epoch() }
func (p *epochProbe) delta() uint64 { return p.m.gate.Epoch() - p.base }

// TestEpochLedger 逐行对齐 NRCP §10.5 的 epoch 递增表
//
// 这是本模块最容易写错、也最要命的地方：少递增一次，已经进入 Provider 队列的旧命令
// 就不会被废止；多递增一次，一条本该有效的租约会莫名失效。因此逐个边界断言【精确的】
// 增量，而不是「有没有变」
func TestEpochLedger(t *testing.T) {
	tests := []struct {
		name string
		want uint64
		run  func(t *testing.T, p *epochProbe)
	}{
		{
			name: "从 NONE 签发新租约",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, humanReq(1))
			},
		},
		{
			name: "HUMAN 抢占 AI 只递增一次",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, aiReq(1))
				p.reset() // 上面那次签发不计入
				mustAcquire(t, p.m, humanReq(2))
			},
		},
		{
			name: "主动释放",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				l := mustAcquire(t, p.m, humanReq(1))
				p.reset()
				if err := p.m.Release(l.ID, l.Conn); err != nil {
					t.Fatalf("Release: %v", err)
				}
			},
		},
		{
			name: "连接断开",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, humanReq(1))
				p.reset()
				p.m.RevokeConn(1)
			},
		},
		{
			name: "同一租约续租不递增",
			want: 0,
			run: func(t *testing.T, p *epochProbe) {
				l := mustAcquire(t, p.m, humanReq(1))
				p.reset()
				if _, err := p.m.Renew(l.ID, l.Conn); err != nil {
					t.Fatalf("Renew: %v", err)
				}
			},
		},
		{
			name: "同连接重复申请视为幂等续租，不递增",
			want: 0,
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, humanReq(1))
				p.reset()
				mustAcquire(t, p.m, humanReq(1))
			},
		},
		{
			name: "普通命令复核不递增",
			want: 0,
			run: func(t *testing.T, p *epochProbe) {
				l := mustAcquire(t, p.m, humanReq(1))
				p.reset()
				for i := 0; i < 10; i++ {
					if _, err := p.m.Check(l.ID, l.Conn); err != nil {
						t.Fatalf("Check: %v", err)
					}
					if err := p.m.Refresh(l.ID, l.Conn); err != nil {
						t.Fatalf("Refresh: %v", err)
					}
				}
			},
		},
		{
			name: "租约到期",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				// 用 AI 类别隔离出「纯 deadline 到期」：它不要求 deadman，
				// 否则 HUMAN 的 300ms 新鲜度窗口会先一步触发，测的就不是这条边界了
				req := aiReq(1)
				req.TTL = 50 * time.Millisecond
				l := mustAcquire(t, p.m, req)
				p.reset()
				p.m.onTick(l.Deadline.Add(time.Millisecond))
			},
		},
		{
			name: "deadman 失效",
			want: 1,
			run: func(t *testing.T, p *epochProbe) {
				l := mustAcquire(t, p.m, humanReq(1))
				p.reset()
				// deadline 还远（HUMAN TTL 2s），但新鲜度窗口 300ms 已过
				p.m.onTick(l.IssuedAt.Add(400 * time.Millisecond))
			},
		},
		{
			name: "Safety 触发后 control 不再叠加递增",
			want: 1, // 这 1 次来自 gate.Trip 自己
			run: func(t *testing.T, p *epochProbe) {
				mustAcquire(t, p.m, humanReq(1))
				p.reset()
				p.m.gate.Trip()
				p.m.RevokeAll(p.m.gate.Epoch())
				p.m.onTick(time.Now()) // 记账不改 epoch
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := newTestModule(t)
			p := &epochProbe{m: m}
			p.reset()

			tc.run(t, p)

			if got := p.delta(); got != tc.want {
				t.Fatalf("epoch delta = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestTripInvalidatesLeaseImmediately 断言「锁存在触发点即刻生效」：不依赖任何 Lane
// 调度，也不等 RevokeAll——Check 立刻就该拒绝（架构 §14.1）
func TestTripInvalidatesLeaseImmediately(t *testing.T) {
	m, g, _ := newTestModule(t)
	l := mustAcquire(t, m, humanReq(1))

	if _, err := m.Check(l.ID, l.Conn); err != nil {
		t.Fatalf("Check before trip: %v", err)
	}

	g.Trip()

	if _, err := m.Check(l.ID, l.Conn); !errors.Is(err, ErrSafetyLatched) {
		t.Fatalf("Check after trip = %v, want ErrSafetyLatched", err)
	}
}

// TestRevokeAllClearsSlotWithoutBump 断言 RevokeAll 只清槽、不递增 epoch，
// 并把被撤的租约交给 Lane 事后记账
func TestRevokeAllClearsSlotWithoutBump(t *testing.T) {
	m, g, rec := newTestModule(t)
	mustAcquire(t, m, humanReq(1))

	g.Trip() // safety 自己那一次递增
	ep := g.Epoch()

	m.RevokeAll(ep)
	if got := g.Epoch(); got != ep {
		t.Fatalf("epoch = %d after RevokeAll, want unchanged %d", got, ep)
	}
	if m.cur.Load() != nil {
		t.Fatal("RevokeAll should have cleared the lease slot")
	}

	m.onTick(time.Now())
	if !rec.has(actionRevoked) {
		t.Fatalf("expected a control.%s audit event, got %v", actionRevoked, rec.actions())
	}
}
