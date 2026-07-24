// 本文件是 Control Lane（SCHED_RR / scheduler.PrioControl = 40）的循环：只做租约的
// 到期检测与撤销记账，不下发任何命令
//
// 为什么到期检测要占一条实时 Lane：deadman 是人一松手就必须失去控制权的看门狗，
// 被普通负载拖到几十毫秒之后才发现，机器人就多走了那么久。命令下发落地后会复用这条
// 同一 Lane（scheduler.PrioControl 的注释即为此预留）
//
// 注意本 Lane 不适用 Safety Stop Lane 的零堆分配硬规则：那条规则针对急停投递路径，
// 本 Lane 不在急停路径上，且优先级 40 低于 PREEMPT_RT threaded IRQ 的 50，按
// internal/scheduler 的取值理由允许等 I/O，因此可以直接在这里落审计
package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
)

// runLane 是 Control Lane 的主循环：只在 ticker 与停机信号上等待，不做任意 I/O
func (m *Module) runLane(ctx context.Context) {
	ticker := time.NewTicker(laneTick)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			m.onTick(t)
		}
	}
}

// onTick 检查一次到期与待记账的撤销
//
// 空闲（无租约、无待记账撤销）时全程无锁，只做两次原子 Load 就返回：mu 会被普通
// 优先级的控制面路径持有，本 Lane 每 10ms 去抢一次纯属自找优先级反转
func (m *Module) onTick(now time.Time) {
	if m.revHead.Load() != m.revTail.Load() {
		m.drainRevoked()
	}

	l := m.cur.Load()
	if l == nil {
		return
	}
	cause := m.leaseState(l, now)
	if cause == nil {
		return
	}
	// Safety 已锁存或 epoch 已被撤销：这条边界属于 safety，epoch 它已经递增过，
	// 租约也会由 RevokeAll 收走。这里不抢着处理，否则会多递增一次 epoch
	if errors.Is(cause, ErrSafetyLatched) || errors.Is(cause, ErrStaleEpoch) {
		return
	}

	// 确实到期了才取锁，取锁后重核一次 - 锁前的判断可能已过时：一次 Refresh 可能刚
	// 把新鲜度顶上来，或租约已被续租（换了新指针）/被 RevokeAll 收走。不重核就会把一条
	// 又变有效的租约误撤。
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := m.cur.Load()
	if cur != l {
		return // 已被续租换成新值，或已被别的路径收走
	}
	// 用同一 tick 时间重核，但会重新读取 m.fresh - 竞态正是锁前判过期、锁后 fresh 已被
	// Refresh 顶上来，重读 freshness 即可挡住，不必换用 time.Now（换了还会破坏用
	// 合成时间驱动到期的测试）。
	cause = m.leaseState(l, now)
	if cause == nil ||
		errors.Is(cause, ErrSafetyLatched) || errors.Is(cause, ErrStaleEpoch) {
		return
	}
	m.dropLocked(l, actionFor(cause), cause)
}

// actionFor 把失效原因映射成审计 Action，让 deadman 失效与单纯的租约到期在离线
// 分析里可分 - 两者的产品含义完全不同：一个是链路/人失联，一个是正常的时限到了
func actionFor(cause error) string {
	if errors.Is(cause, ErrDeadmanExpired) {
		return actionDeadmanExpired
	}
	return actionExpired
}

// drainRevoked 补记 RevokeAll 交办的撤销审计，排空整个环。
//
// RevokeAll 跑在 Safety Supervisor Lane（FIFO 90）上，只做原子写；把字符串格式化与
// 审计写入挪到这里，是为了不让一条高优先级的安全路径去等普通优先级的审计设施。
//
// 单消费者：运行期只有 Control Lane 调用，Stop 只在 Lane 退出后调用（见 Module.Stop），
// 二者不并发，故 revTail 无需 CAS，也不需要持 mu（读的是不可变 Lease 值与它的 epoch）。
func (m *Module) drainRevoked() {
	for {
		tail := m.revTail.Load()
		if tail >= m.revHead.Load() {
			break
		}
		i := tail & (revokedRingSize - 1)
		l := m.revLease[i].Load()
		if l == nil {
			break // 生产者已发布 head 但尚未写完这格，下次再来
		}
		epoch := m.revEpoch[i].Load()
		m.revLease[i].Store(nil)
		m.revTail.Store(tail + 1)

		m.aud.Record(context.Background(), audit.Event{
			Action:  "control." + actionRevoked,
			Subject: l.Owner.String(),
			Denied:  true,
			Err:     errSafetyRevoked,
			Detail: fmt.Sprintf("lease=%s class=%s resource=%s epoch=%d halt_epoch=%d",
				l.ID, l.Class, l.Resource, l.Epoch, epoch),
		})
	}
	if n := m.revDropped.Swap(0); n > 0 {
		m.aud.Record(context.Background(), audit.Event{
			Action:  "control.RevokeAuditDropped",
			Subject: "kernel",
			Denied:  true,
			Detail:  fmt.Sprintf("dropped=%d", n),
		})
	}
}
