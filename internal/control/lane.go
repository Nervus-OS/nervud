// 本文件是 Control Lane (SCHED_RR / scheduler.PrioControl = 40) 的循环: 只做租约的
// 到期检测与撤销记账, 不下发任何命令
//
// 为什么到期检测要占一条实时 Lane: deadman 是人一松手就必须失去控制权的看门狗,
// 被普通负载拖到几十毫秒之后才发现, 机器人就多走了那么久. 命令下发落地后会复用这条
// 同一 Lane (scheduler.PrioControl 的注释即为此预留)
//
// 注意本 Lane 不适用 Safety Stop Lane 的零堆分配硬规则: 那条规则针对急停投递路径,
// 本 Lane 不在急停路径上, 且优先级 40 低于 PREEMPT_RT threaded IRQ 的 50, 按
// internal/scheduler 的取值理由允许等 I/O, 因此可以直接在这里落审计
package control

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
)

// runLane 是 Control Lane 的主循环: 只在 ticker 与停机信号上等待, 不做任意 I/O
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
// 空闲 (无租约, 无待记账撤销) 时全程无锁: 读一次不可变槽快照并逐槽原子 Load.
// mu 会被普通优先级的控制面路径持有, 本 Lane 每 10ms 去抢一次纯属优先级反转.
func (m *Module) onTick(now time.Time) {
	if m.revPending.Load() != 0 {
		m.drainRevoked()
	}

	for _, slot := range m.slots.Load().all {
		l := slot.cur.Load()
		if l == nil {
			continue
		}
		cause := m.leaseState(slot, l, now)
		if cause == nil {
			continue
		}
		// Safety 已锁存或 epoch 已被撤销: 这条边界属于 safety, epoch 它已经递增过,
		// 租约也会由 RevokeAll 收走. 这里不抢着处理, 否则会多递增一次 epoch.
		if errors.Is(cause, ErrSafetyLatched) || errors.Is(cause, ErrStaleEpoch) {
			continue
		}

		// 确实到期了才取锁, 取锁后重核一次. 其它槽的边界可能已把本槽换代成新指针,
		// Refresh 也可能刚刷新本槽 freshness; 两种情况都不能误撤.
		m.mu.Lock()
		cur := slot.cur.Load()
		if cur == l {
			cause = m.leaseState(slot, l, now)
			if cause != nil &&
				!errors.Is(cause, ErrSafetyLatched) && !errors.Is(cause, ErrStaleEpoch) {
				m.dropLocked(slot, l, actionFor(cause), cause)
			}
		}
		m.mu.Unlock()
	}
}

// actionFor 把失效原因映射成审计 Action, 让 deadman 失效与单纯的租约到期在离线
// 分析里可分 - 两者的产品含义完全不同: 一个是链路/人失联, 一个是正常的时限到了
func actionFor(cause error) string {
	if errors.Is(cause, ErrDeadmanExpired) {
		return actionDeadmanExpired
	}
	return actionExpired
}

// drainRevoked 补记 RevokeAll 交办的撤销审计, 排空所有槽的待处理位置.
//
// RevokeAll 跑在 Safety Supervisor Lane (FIFO 90) 上, 只做原子写; 把字符串格式化与
// 审计写入挪到这里, 是为了不让一条高优先级的安全路径去等普通优先级的审计设施.
//
// Control Lane, Acquire (下一条租约发布前的顺序屏障) 与 Stop 都可能消费, revDrainMu
// 将它们串行化. 该锁只存在于普通优先级 drain 路径; RevokeAll 不取锁.
func (m *Module) drainRevoked() {
	m.revDrainMu.Lock()
	defer m.revDrainMu.Unlock()

	for _, slot := range m.slots.Load().all {
		l := slot.revoked.Swap(nil)
		if l == nil {
			continue
		}
		epoch := slot.revokedEpoch.Load()
		m.notifyLeaseEnded(l)
		m.aud.Record(context.Background(), audit.Event{
			Action:  "control." + actionRevoked,
			Subject: l.Owner.String(),
			Denied:  true,
			Err:     errSafetyRevoked,
			Detail: fmt.Sprintf("lease=%s class=%s resource=%s epoch=%d halt_epoch=%d",
				l.ID, l.Class, l.Resource, l.Epoch, epoch),
		})
		// pending 覆盖整个 observer+audit 边界; Acquire 看到非零会等待 revDrainMu,
		// 不会让迟到的旧 ControlLeaseEnded 误伤同 conn/resource 的新租约派生状态.
		m.revPending.Add(^uint64(0))
	}
}
