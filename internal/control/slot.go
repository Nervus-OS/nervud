// 见 doc.go 的包说明
//
// 本文件是租约槽的状态机：签发、续租、新鲜度、释放、撤销与派发前复核
//
// motion epoch 的递增点严格按 NRCP §10.5 的表，每个边界【恰好一次】：
//
//	从 NONE 签发                      递增（issueLocked）
//	HUMAN 抢占 AI                     递增一次（作废旧租约不递增，随后的签发递增）
//	释放 / 超时 / 断线 / deadman 失效  递增（dropLocked）
//	同一租约续租                       不递增
//	Safety 触发                        不在本包递增（gate.Trip 已经递增过，RevokeAll 只清槽）
package control

import (
	"fmt"
	"time"

	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/motiongate"
)

// Request 是一次控制权申请
//
// Class 必须由调用方（IPC 请求管线：身份 + Permission + Policy）裁决后填入，
// 本包不接受任何自报值——远程手机在 payload 里写 source=HUMAN 一律不可信
type Request struct {
	Conn     ConnID
	Class    Class
	Resource string
	Owner    identity.Caller

	// TTL/Deadman 为 0 表示沿用 Policy 默认；非 0 时只能比 Policy 更严（更短），
	// 超限即拒绝而不是静默压短（理由见 ErrPolicyViolation）
	TTL     time.Duration
	Deadman time.Duration
}

// Acquire 申请控制权
//
// 判定顺序与 Agent 文档 §3.3 一致：Safety 先于一切，然后才谈 HUMAN/AI 的相对关系
func (m *Module) Acquire(req Request) (Lease, error) {
	ttl, deadman, err := m.resolveRequest(req)
	if err != nil {
		m.recordDenied(req, err)
		return Lease{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 停机后拒绝新签发。Stop 关 stopCh 后到期 Lane 会退出，此时若还能签出租约，就没有
	// 任何 Lane 再为它做到期清槽/epoch 撤销——它能一直通过 Check 授权运动直到进程退出。
	// 检查在持 mu 内做，与 Stop 的最终撤租排定顺序：先关 stopCh 的 Stop 必然拒掉后来的
	// Acquire；先拿到 mu 的 Acquire 签出的租约由随后 Stop 的撤租收掉
	if m.stopping() {
		m.recordDenied(req, ErrShuttingDown)
		return Lease{}, ErrShuttingDown
	}

	// now 在持 mu 后再取：放锁外会让一个晚提交的旧调用用更早的时间盖掉更新的 deadline
	now := time.Now()

	// Safety 非 NORMAL 一律不签发。锁存期间恢复控制权只能走 OEM Recovery / re-arm，
	// 不能靠重新申请（NRCP §14.4：re-arm 后仍从 NONE 开始）
	if st, _ := m.gate.Snapshot(); st != motiongate.StateNormal {
		m.recordDenied(req, ErrSafetyLatched)
		return Lease{}, ErrSafetyLatched
	}

	if old := m.cur.Load(); old != nil {
		if invalid := m.leaseState(old, now); invalid != nil {
			// 在持租约已经失效，只是 Control Lane 还没来得及收。这本身就是一次
			// 撤销边界，按 §10.5 递增一次；随后的签发再递增一次，两次都合法
			m.dropLocked(old, actionFor(invalid), invalid)
		} else {
			switch {
			case old.Conn == req.Conn && old.Class == req.Class:
				// 同连接同类别的重复申请 = 幂等续租，不是抢占，不递增 epoch。
				// SDK 重发/重连时不该让机器人的 epoch 无谓抖动
				return m.renewLocked(old, now)

			case canPreempt(req.Class, old.Class):
				// 唯一合法抢占：HUMAN 抢 AI。旧租约就地作废但【不】在这里递增——
				// §10.5 要求整个抢占只递增一次，那一次留给下面的签发
				m.cur.Store(nil)
				m.recordLease(actionPreempted, old, nil)

			case old.Class == ClassHuman:
				// 人正在遥控。上层据此可以去问用户「要不要让出」——让出的决定权
				// 在人，不在申请者，所以这里只拒绝，不做任何自动接管
				m.recordDenied(req, ErrHeldByHuman)
				return Lease{}, ErrHeldByHuman

			default:
				m.recordDenied(req, ErrHeldByAI)
				return Lease{}, ErrHeldByAI
			}
		}
	}

	return m.issueLocked(req, now, ttl, deadman)
}

// resolveRequest 校验申请并把 TTL/deadman 与 Policy 上限合成为最终取值
func (m *Module) resolveRequest(req Request) (time.Duration, time.Duration, error) {
	if req.Conn == 0 {
		return 0, 0, fmt.Errorf("%w: connection id is zero", ErrInvalidRequest)
	}
	if !req.Class.Valid() {
		// 包括「客户端试图申请 NONE」这种情况：NONE 不是可申请的类别
		return 0, 0, fmt.Errorf("%w: controller class %d is not HUMAN or AI", ErrInvalidRequest, req.Class)
	}
	if req.Resource != ResourceBaseMain {
		return 0, 0, fmt.Errorf("%w: %q", ErrUnknownResource, req.Resource)
	}
	return m.policy.forClass(req.Class).resolve(req.TTL, req.Deadman)
}

// issueLocked 签发一条新租约。调用方必须持有 mu
func (m *Module) issueLocked(req Request, now time.Time, ttl, deadman time.Duration) (Lease, error) {
	// §10.5：先废止旧 Lease/队列，再以新 epoch 签发新 Lease
	m.cur.Store(nil)

	// 「仅 Normal 才递增」必须原子。若在「读 State == Normal」与「BumpEpoch」之间被
	// 一次 Trip 插入，旧写法会把【已锁存】的 Gate 又推进一代——于是 Safety 的投递路径
	// （deliverHalt 读 Epoch）与跟踪路径（Supervisor 的 haltEpoch）各持相邻两个 epoch，
	// Provider 的有效回报会被当成陈旧报告忽略，并进而假触发超时升级。BumpEpochIfNormal
	// 把「检查 + 递增」并成一次 CAS，锁存即拒发、绝不推进。
	epoch, ok := m.gate.BumpEpochIfNormal()
	if !ok {
		m.recordDenied(req, ErrSafetyLatched)
		return Lease{}, ErrSafetyLatched
	}

	l := Lease{
		ID:       newID(),
		Conn:     req.Conn,
		Class:    req.Class,
		Resource: req.Resource,
		Owner:    req.Owner,
		IssuedAt: now,
		Deadline: now.Add(ttl),
		TTL:      ttl,
		Epoch:    epoch,
		Deadman:  deadman,
	}
	// 先置新鲜度再发布：否则一条紧跟着发布的 Check 会读到上一条租约留下的旧
	// fresh，把新租约误判成 deadman 已失效
	m.markFresh(now)
	m.cur.Store(&l)

	// 发布后复核（包文档并发规则 3）。Safety 触发不取 mu，因此签发与 Trip 可能
	// 交错；这一步保证「诞生即失效」的租约不会留在槽里
	if st, ep := m.gate.Snapshot(); st != motiongate.StateNormal || ep != epoch {
		m.cur.CompareAndSwap(&l, nil)
		cause := ErrSafetyLatched
		if st == motiongate.StateNormal {
			cause = ErrStaleEpoch
		}
		m.recordDenied(req, cause)
		return Lease{}, cause
	}

	m.recordLease(actionGranted, &l, nil)
	return l, nil
}

// Renew 续租：延长 deadline 并刷新新鲜度，不递增 epoch（§10.5：租约身份不变）
func (m *Module) Renew(id ID, conn ConnID) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// now 在持 mu 后取：放锁外会让一个晚提交的旧 Renew 用更早的时间盖掉更新的 deadline
	now := time.Now()

	l, err := m.lookup(id, conn, now)
	if err != nil {
		return time.Time{}, err
	}
	renewed, err := m.renewLocked(l, now)
	if err != nil {
		return time.Time{}, err
	}
	return renewed.Deadline, nil
}

// renewLocked 用一条新的不可变值整体替换旧租约（ID 不变）。调用方必须持有 mu
func (m *Module) renewLocked(l *Lease, now time.Time) (Lease, error) {
	next := *l
	next.Deadline = now.Add(l.TTL)

	if !m.cur.CompareAndSwap(l, &next) {
		// 期间被 RevokeAll 清掉了（Safety 触发）。不重试：此刻已经没有控制权
		return Lease{}, ErrSafetyLatched
	}
	// 心跳既延期也证明活着，因此续租同时刷新 deadman 新鲜度
	m.markFresh(now)
	m.recordLease(actionRenewed, &next, nil)
	return next, nil
}

// Refresh 只刷新命令新鲜度，不动 deadline
//
// 无锁、零堆分配：每条运动命令都会调用它来证明「输入还是新的」
func (m *Module) Refresh(id ID, conn ConnID) error {
	now := time.Now()
	if _, err := m.lookup(id, conn, now); err != nil {
		return err
	}
	m.markFresh(now)
	return nil
}

// Release 主动释放控制权：撤租、递增 epoch、回到 NONE
//
// 刻意不复核租约是否仍有效：释放一条刚过期的租约应当成功而不是报错，调用方的意图
// 已经达成了。dropLocked 的 CAS 保证不会重复递增
func (m *Module) Release(id ID, conn ConnID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l := m.cur.Load()
	if l == nil || l.ID != id || l.Conn != conn {
		return ErrControlNotHeld
	}
	m.dropLocked(l, actionReleased, nil)
	return nil
}

// RevokeConn 撤销某条连接持有的租约：连接断开、手机退后台、远程会话失效时调用
// （§10.5：立即递增 epoch，撤销 Lease，进入 NONE）
func (m *Module) RevokeConn(conn ConnID) {
	if conn == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	l := m.cur.Load()
	if l == nil || l.Conn != conn {
		return
	}
	m.dropLocked(l, actionRevoked, errConnectionClosed)
}

// RevokeAll 撤销全部执行器租约，满足 safety 侧的 LeaseRevoker
//
// 由 Safety Supervisor Lane（FIFO 90）在锁存后同步调用，因此有三条硬约束：
//
//   - 【不取 mu】。Go 的 mutex 没有优先级继承，等一个普通优先级的持锁者就是
//     FIFO 90 上的优先级反转。这里只做原子操作
//   - 【不递增 epoch】。§10.5 要求每个边界只递增一次，而 gate.Trip() 已经递增过了
//   - 【零堆分配】。绝不 new——把被撤租约与它的 halt epoch 写进预分配的定长环
//
// 单生产者（本函数只由 Supervisor 一个 goroutine 调用），故 revHead 无需 CAS。
// 审计交给 Control Lane 事后补：审计要格式化字符串，不该发生在这条同步路径上。
func (m *Module) RevokeAll(epoch uint64) {
	old := m.cur.Swap(nil)
	if old == nil {
		return
	}
	head := m.revHead.Load()
	if head-m.revTail.Load() >= revokedRingSize {
		m.revDropped.Add(1) // 环满（极少见）：仅降级审计，撤租本身已由 Swap 完成
		return
	}
	i := head & (revokedRingSize - 1)
	m.revEpoch[i].Store(epoch)
	m.revLease[i].Store(old) // 后写 lease：消费者以它非 nil 为「该格已就绪」的标志
	m.revHead.Store(head + 1)
}

// Check 是派发前的控制权复核，返回可放进 ExecutionContext 的当前 motion epoch
//
// 无锁、零堆分配：每条运动命令走一次（由 AllocsPerRun 测试守住）。
// 它复核 §10.5 里属于本模块的那几条前置：有效租约 + Safety NORMAL + epoch 未过期 +
// deadline 未到 + deadman 新鲜。sequence 与单条命令的 deadline 属于调用侧
func (m *Module) Check(id ID, conn ConnID) (uint64, error) {
	l, err := m.lookup(id, conn, time.Now())
	if err != nil {
		return 0, err
	}
	return l.Epoch, nil
}

// ControlSnapshot 返回控制面的一致只读快照
//
// 只读一次 Gate，把这次读到的 (st, ep) 同时用于「来源判定」与「租约有效性复核」。
// 读两次会撕裂：并发 Trip/re-arm 时可能返回 Snapshot.Epoch != Lease.Epoch，或报出
// 已过时的 NORMAL/来源。
func (m *Module) ControlSnapshot() Snapshot {
	st, ep := m.gate.Snapshot()
	s := Snapshot{State: st, Epoch: ep}

	// Safety 非 NORMAL 时有效控制来源恒为 SAFETY，与槽里是否还残留租约无关
	if st != motiongate.StateNormal {
		s.Source = SourceSafety
		return s
	}

	l := m.cur.Load()
	if l == nil || m.leaseStateAt(l, st, ep, time.Now()) != nil {
		s.Source = SourceNone
		return s
	}
	s.Held = true
	s.Lease = *l
	if l.Class == ClassHuman {
		s.Source = SourceHuman
	} else {
		s.Source = SourceAI
	}
	return s
}

// lookup 取出与 (id, conn) 匹配且此刻仍然有效的租约
//
// 无锁、零堆分配：只读原子量，返回的错误全是预分配哨兵
func (m *Module) lookup(id ID, conn ConnID, now time.Time) (*Lease, error) {
	l := m.cur.Load()
	// 租约不能转让：ID 与连接必须同时对上（§10.2 owner_connection）
	if l == nil || l.ID != id || l.Conn != conn {
		return nil, ErrControlNotHeld
	}
	if err := m.leaseState(l, now); err != nil {
		return nil, err
	}
	return l, nil
}

// leaseState 复核一条租约此刻是否仍能授权运动，nil 表示有效。读一次 Gate 后转交
// leaseStateAt。
func (m *Module) leaseState(l *Lease, now time.Time) error {
	st, ep := m.gate.Snapshot()
	return m.leaseStateAt(l, st, ep, now)
}

// leaseStateAt 用【已经读好的】(st, ep) 复核租约有效性，让调用方能把一次 Gate 读同时
// 用于别的判定（见 ControlSnapshot），避免同一逻辑里读两次 Gate 产生撕裂。
//
// 顺序即优先级：Safety > epoch > deadline > deadman。先报最根本的原因，调用者据此
// 决定是「重新申请」还是「等 re-arm」。
func (m *Module) leaseStateAt(l *Lease, st motiongate.State, ep uint64, now time.Time) error {
	if st != motiongate.StateNormal {
		return ErrSafetyLatched
	}
	// epoch 不符本身就是一条 fail-closed 判据：任何撤销边界都会递增 Gate 的 epoch，
	// 因此即便撤销动作因故没跑完，陈旧租约也授权不了运动
	if ep != l.Epoch {
		return ErrStaleEpoch
	}
	if now.After(l.Deadline) {
		return ErrLeaseExpired
	}
	if l.Deadman > 0 && now.Sub(m.base)-time.Duration(m.fresh.Load()) > l.Deadman {
		return ErrDeadmanExpired
	}
	return nil
}

// markFresh 记下一次新鲜输入，存相对单调基准的纳秒（见 Module.fresh 的说明）。
//
// 只增不减（原子 max）：单调时钟下更晚的调用总是更大的值，因此这只会挡住一个晚提交的
// 【旧】调用把新鲜度倒写回去——正是要防的竞态：两个并发 Refresh 里较早那次晚落地时，
// 若无条件 Store 会把 freshness 从约 20ms 打回 0，令有效租约提前 deadman。零堆分配。
func (m *Module) markFresh(now time.Time) {
	v := int64(now.Sub(m.base))
	for {
		cur := m.fresh.Load()
		if v <= cur {
			return
		}
		if m.fresh.CompareAndSwap(cur, v) {
			return
		}
	}
}

// dropLocked 撤下一条租约并递增 epoch。调用方必须持有 mu
//
// 用 CAS 而不是无条件 Store(nil)：CAS 失败说明这条租约已经被别的路径收走了——通常
// 是 RevokeAll（safety 的 RT 路径，不取 mu，因此能与本函数交错）。那条边界的 epoch
// 已由 gate.Trip 递增、审计也由 Lane 的撤销记账路径补，这里必须安静退出，否则会多
// 记出重复审计。
//
// 递增用 BumpEpochIfNormal 而不是无条件 BumpEpoch：若 Gate 已被 Trip 锁存（而 RevokeAll
// 尚未把这条租约 Swap 走，CAS 仍成功），无条件递增会把已锁存的 Gate 又推进一代，令
// Safety 的投递/跟踪 epoch 错开。锁存时那条撤销边界已被 Trip 的递增涵盖，这里不再叠加。
func (m *Module) dropLocked(l *Lease, action string, cause error) {
	if !m.cur.CompareAndSwap(l, nil) {
		return
	}
	m.gate.BumpEpochIfNormal()
	m.recordLease(action, l, cause)
}
