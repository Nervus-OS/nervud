// 本文件是租约槽的状态机：签发、续租、新鲜度、释放、撤销与派发前复核
//
// motion epoch 的递增点严格按 的表，每个边界恰好一次：
//
//	从 NONE 签发           递增（issueLocked）
//	HUMAN 抢占 AI           递增一次（作废旧租约不递增，随后的签发递增）
//	释放 / 超时 / 断线 / deadman 失效 递增（dropLocked）
//	同一租约续租            不递增
//	Safety 触发            不在本包递增（gate.Trip 已经递增过，RevokeAll 只清槽）
package control

import (
	"fmt"
	"time"

	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/motiongate"
)

// Request 是一次控制权申请
//
// Class 是上层策略传入的控制主体类别。当前 IPC 策略允许 wire 调用方选择 HUMAN/AI
// 并单独审计该选择；本包不做身份推断，只执行既定抢占矩阵与租约时序。
type Request struct {
	Conn  ConnID
	Class Class
	// Resource 必须是上层从 catalog 解析、确认 access_mode=EXCLUSIVE_CONTROL 后传入的
	// 稳定公开 handle。control 刻意不 import catalog，只做非空良构校验与按 handle 隔离。
	Resource           string
	ResourceGeneration uint64
	Owner              identity.Caller

	// TTL/Deadman 为 0 表示沿用 Policy 默认；非 0 时只能比 Policy 更严（更短），
	// 超限即拒绝而不是静默压短（理由见 ErrPolicyViolation）
	TTL     time.Duration
	Deadman time.Duration

	// RequestedTTL 是 wire 的偏好值：大于 0 时取 min(RequestedTTL, Policy TTL)，
	// 不因客户端偏好超过上限而拒绝。它与严格的 TTL 不能同时设置。
	RequestedTTL time.Duration
}

// Acquire 申请控制权
//
// Safety 必须先于 HUMAN/AI 判定，否则锁存后仍可能签发可用租约
func (m *Module) Acquire(req Request) (Lease, error) {
	ttl, deadman, err := m.resolveRequest(req)
	if err != nil {
		m.recordDenied(req, err)
		return Lease{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Safety 撤租的观察者通知必须先于下一条租约发布。否则同一 conn/resource
	// 很快 re-arm 并重获控制权时，延后的 RevokeControl 会误伤新租约派生的流。
	// drainRevoked 用独立消费者锁与 Control Lane 串行化；这里仍是普通控制面，
	// 不在 RevokeAll 的 RT 路径上。
	if m.revPending.Load() != 0 {
		m.drainRevoked()
	}

	// 停机后拒绝新签发。Stop 关 stopCh 后到期 Lane 会退出，此时若还能签出租约，就没有
	// 任何 Lane 再为它做到期清槽/epoch 撤销 - 它能一直通过 Check 授权运动直到进程退出。
	// 检查在持 mu 内做，与 Stop 的最终撤租排定顺序：先关 stopCh 的 Stop 必然拒掉后来的
	// Acquire；先拿到 mu 的 Acquire 签出的租约由随后 Stop 的撤租收掉
	if m.stopping() {
		m.recordDenied(req, ErrShuttingDown)
		return Lease{}, ErrShuttingDown
	}

	// now 在持 mu 后再取：放锁外会让一个晚提交的旧调用用更早的时间盖掉更新的 deadline
	now := time.Now()

	// Safety 非 NORMAL 一律不签发。锁存期间恢复控制权只能走 OEM Recovery / re-arm，
	// 不能靠重新申请（re-arm 后仍从 NONE 开始）
	if st, _ := m.gate.Snapshot(); st != motiongate.StateNormal {
		m.recordDenied(req, ErrSafetyLatched)
		return Lease{}, ErrSafetyLatched
	}

	slot := m.slotLocked(req.Resource)
	if slot == nil {
		m.recordDenied(req, ErrResourceCapacity)
		return Lease{}, ErrResourceCapacity
	}
	if old := slot.cur.Load(); old != nil {
		if old.ResourceGeneration != req.ResourceGeneration {
			// The public handle was republished with different semantics. Treat the
			// old lease as revoked before applying class/preemption policy to the
			// new definition.
			m.dropLocked(slot, old, actionRevoked, errResourceRevoked)
		} else if invalid := m.leaseState(slot, old, now); invalid != nil {
			// 在持租约已经失效，只是 Control Lane 还没来得及收。这本身就是一次
			// 撤销边界，按 递增一次；随后的签发再递增一次，两次都合法
			m.dropLocked(slot, old, actionFor(invalid), invalid)
		} else {
			switch {
			case old.Conn == req.Conn && old.Class == req.Class:
				// 同连接同类别的重复申请 = 幂等续租，不是抢占，不递增 epoch。
				// SDK 重发/重连时不该让机器人的 epoch 无谓抖动
				return m.renewLocked(slot, old, now)

			case canPreempt(req.Class, old.Class):
				// 唯一合法抢占：HUMAN 抢 AI。旧租约就地作废但不在这里递增 -
				// 要求整个抢占只递增一次，那一次留给下面的签发
				//
				// RevokeAll 可不取 mu 并发清槽，所以这里仍须 CAS。只有真正收走
				// old 的路径才记账、通知观察者；CAS 失败说明 Safety 路径拥有该
				// 撤销边界，随后会由 drainRevoked 通知，不能重复发送。
				if slot.cur.CompareAndSwap(old, nil) {
					m.notifyLeaseEnded(old)
					m.recordLease(actionPreempted, old, nil)
				}

			case old.Class == ClassHuman:
				// 人正在遥控。上层据此可以去问用户要不要让出 - 让出的决定权
				// 在人，不在申请者，所以这里只拒绝，不做任何自动接管
				m.recordDenied(req, ErrHeldByHuman)
				return Lease{}, ErrHeldByHuman

			default:
				m.recordDenied(req, ErrHeldByAI)
				return Lease{}, ErrHeldByAI
			}
		}
	}

	return m.issueLocked(slot, req, now, ttl, deadman)
}

// resolveRequest 校验申请并把 TTL/deadman 与 Policy 上限合成为最终取值
func (m *Module) resolveRequest(req Request) (time.Duration, time.Duration, error) {
	if req.Conn == 0 {
		return 0, 0, fmt.Errorf("%w: connection id is zero", ErrInvalidRequest)
	}
	if !req.Class.Valid() {
		// 包括客户端试图申请 NONE这种情况：NONE 不是可申请的类别
		return 0, 0, fmt.Errorf("%w: controller class %d is not HUMAN or AI", ErrInvalidRequest, req.Class)
	}
	if req.Resource == "" {
		return 0, 0, fmt.Errorf("%w: %q", ErrUnknownResource, req.Resource)
	}
	if req.ResourceGeneration == 0 {
		return 0, 0, fmt.Errorf("%w: resource generation is zero", ErrInvalidRequest)
	}
	classPolicy := m.policy.forClass(req.Class)
	if req.RequestedTTL < 0 {
		return 0, 0, fmt.Errorf("%w: negative requested ttl", ErrInvalidRequest)
	}
	if req.RequestedTTL > 0 {
		if req.TTL != 0 {
			return 0, 0, fmt.Errorf("%w: ttl and requested ttl are mutually exclusive", ErrInvalidRequest)
		}
		ttl := min(req.RequestedTTL, classPolicy.TTL)
		deadman := req.Deadman
		if deadman == 0 && classPolicy.Deadman > ttl {
			deadman = ttl
		}
		return classPolicy.resolve(ttl, deadman)
	}
	return classPolicy.resolve(req.TTL, req.Deadman)
}

// issueLocked 签发一条新租约。调用方必须持有 mu
func (m *Module) issueLocked(slot *resourceSlot, req Request, now time.Time, ttl, deadman time.Duration) (Lease, error) {
	// 仅 Normal 才递增必须原子。若在读 State == Normal与BumpEpoch之间被
	// 一次 Trip 插入，旧写法会把已锁存的 Gate 又推进一代 - 于是 Safety 的投递路径
	// （deliverHalt 读 Epoch）与跟踪路径（Supervisor 的 haltEpoch）各持相邻两个 epoch，
	// Provider 的有效回报会被当成陈旧报告忽略，并进而假触发超时升级。BumpEpochIfNormal
	// 把检查 + 递增并成一次 CAS，锁存即拒发、绝不推进。
	epoch, ok := m.advanceEpochLocked()
	if !ok {
		m.recordDenied(req, ErrSafetyLatched)
		return Lease{}, ErrSafetyLatched
	}

	// RevokeAll 可能在 Acquire 首次 drain 之后才发布上一条租约的终止事件。
	// 新租约必须等旧事件完成，避免迟到的 RevokeControl 误伤同 conn/resource 的新流。
	if m.revPending.Load() != 0 {
		m.drainRevoked()
	}
	seq := m.revokeSeq.Load()
	if seq&1 != 0 || slot.revoked.Load() != nil {
		m.recordDenied(req, ErrSafetyLatched)
		return Lease{}, ErrSafetyLatched
	}

	l := Lease{
		ID:                 newID(),
		Conn:               req.Conn,
		Class:              req.Class,
		Resource:           req.Resource,
		ResourceGeneration: req.ResourceGeneration,
		Owner:              req.Owner,
		IssuedAt:           now,
		Deadline:           now.Add(ttl),
		TTL:                ttl,
		Epoch:              epoch,
		Deadman:            deadman,
	}
	// 先置新鲜度再发布：否则一条紧跟着发布的 Check 会读到上一条租约留下的旧
	// fresh，把新租约误判成 deadman 已失效
	m.markFresh(slot, now)
	slot.cur.Store(&l)

	// Safety 触发不取 mu，因此签发与 Trip 可能交错。发布后必须复核，
	// 保证诞生即失效的租约不会留在槽里
	if st, ep := m.gate.Snapshot(); st != motiongate.StateNormal || ep != epoch ||
		m.revokeSeq.Load() != seq {
		slot.cur.CompareAndSwap(&l, nil)
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

// Renew 续租：延长 deadline 并刷新新鲜度，不递增 epoch（租约身份不变）
func (m *Module) Renew(id ID, conn ConnID) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// now 在持 mu 后取：放锁外会让一个晚提交的旧 Renew 用更早的时间盖掉更新的 deadline
	now := time.Now()

	slot, l, err := m.lookup(id, conn, now)
	if err != nil {
		return time.Time{}, err
	}
	renewed, err := m.renewLocked(slot, l, now)
	if err != nil {
		return time.Time{}, err
	}
	return renewed.Deadline, nil
}

// renewLocked 用一条新的不可变值整体替换旧租约（ID 不变）。调用方必须持有 mu
func (m *Module) renewLocked(slot *resourceSlot, l *Lease, now time.Time) (Lease, error) {
	next := *l
	next.Deadline = now.Add(l.TTL)

	if !slot.cur.CompareAndSwap(l, &next) {
		// 期间被 RevokeAll 清掉了（Safety 触发）。不重试：此刻已经没有控制权
		return Lease{}, ErrSafetyLatched
	}
	// 心跳既延期也证明活着，因此续租同时刷新 deadman 新鲜度
	m.markFresh(slot, now)
	m.recordLease(actionRenewed, &next, nil)
	return next, nil
}

// Refresh 只刷新命令新鲜度，不动 deadline
//
// 无锁、零堆分配：每条运动命令都会调用它来证明输入还是新的
func (m *Module) Refresh(id ID, conn ConnID) error {
	now := time.Now()
	slot, l, err := m.lookup(id, conn, now)
	if err != nil {
		return err
	}
	m.markFresh(slot, now)
	// A normal revocation can remove the lease between lookup and markFresh.
	// Re-check the identity so a stale command never reports a successful
	// refresh. A replacement lease is issued after now, and markFresh is an
	// atomic max, so this stale timestamp cannot extend the replacement's
	// deadman window.
	if !slotHolds(slot, l) {
		return ErrControlNotHeld
	}
	return nil
}

// Release 主动释放控制权：撤租、递增 epoch、回到 NONE
//
// 刻意不复核租约是否仍有效：释放一条刚过期的租约应当成功而不是报错，调用方的意图
// 已经达成了。dropLocked 的 CAS 保证不会重复递增
func (m *Module) Release(id ID, conn ConnID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	slot, l := m.findLease(id, conn)
	if l == nil {
		return ErrControlNotHeld
	}
	m.dropLocked(slot, l, actionReleased, nil)
	return nil
}

// RevokeConn 撤销某条连接在全部 Resource 上持有的租约：连接断开、手机退后台、
// 远程会话失效时调用（整批只递增一次 epoch）。
func (m *Module) RevokeConn(conn ConnID) {
	if conn == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dropMatchingLocked(func(l *Lease) bool { return l.Conn == conn },
		actionRevoked, errConnectionClosed)
}

// RevokeResource invalidates the lease for one catalog handle. Catalog removal
// and same-handle definition replacement must call this before that handle can
// authorize a newly resolved route; otherwise an old lease could outlive the
// resource generation that justified it.
//
// The slot remains in the immutable directory. Handles are admitted only by
// the trusted catalog, and retaining the slot keeps RevokeAll's Safety read
// side lock-free with stable pointers.
func (m *Module) RevokeResource(resource string, generation uint64) {
	if resource == "" || generation == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	slot := m.slot(resource)
	if slot == nil {
		return
	}
	if l := slot.cur.Load(); l != nil && l.ResourceGeneration == generation {
		m.dropLocked(slot, l, actionRevoked, errResourceRevoked)
	}
}

// RevokeByPackage 撤销某 Package 名下持有的全部执行器租约：包被卸载、或其 motion 组
// 权限被用户撤销时由上层调用（permission.LeaseRevoker / pkgregistry.LeaseRevoker 的
// 窄接口，*Module 隐式满足）。这让权限撤销能立即撤掉该 Package 的执行器租约，
// 而不必等待现有租约自然过期。
//
// 归属判据用租约签发时记下的可信身份 Owner.PackageID（由 IPC 请求管线裁决后填入，
// 见 lease.go 的 Owner 说明），不信任何自报值。遍历所有 Resource 槽，一次撤掉该包
// 当前持有的全部租约。
//
// 与 doc.go 的三条硬规则一致，但此路径不在急停/Safety Supervisor Lane 上 - 它由
// 卸载/撤权的普通优先级流程调用，因此与 RevokeConn/Release 同样取 mu走正常变更路
// 径（不是 RevokeAll 那条免锁的 RT 路径，别把两者互相套用）。撤租经 dropLocked：
//   - 递增 epoch 走 BumpEpochIfNormal（不先读 State 再 Bump；Gate 已锁存时不叠加递增）
//   - 不锁存 Safety（撤租只回到 NONE，不 Trip）
//   - 幂等：pkgID 为空、无租约、或当前租约不属于该包，都直接返回 nil（无 lease 可撤
//     本就是调用方想要的终态 - 包已经没有控制权了）
//
// 返回 error 是为了满足上层窄接口签名；当前内存撤权路径恒为 nil。
func (m *Module) RevokeByPackage(pkgID string) error {
	if pkgID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dropMatchingLocked(func(l *Lease) bool { return l.Owner.PackageID == pkgID },
		actionRevoked, errPackageRevoked)
	return nil
}

// RevokeAll 撤销全部执行器租约，满足 safety 侧的 LeaseRevoker
//
// 由 Safety Supervisor Lane（FIFO 90）在锁存后同步调用，因此有三条硬约束：
//
//   - 不取 mu。Go 的 mutex 没有优先级继承，等一个普通优先级的持锁者就是
//     FIFO 90 上的优先级反转。这里只做原子操作
//   - 不递增 epoch。 要求每个边界只递增一次，而 gate.Trip 已经递增过了
//   - 零堆分配。绝不 new - 扫描不可变槽快照，把撤租约写进每槽预分配位置
//
// 单生产者（本函数只由 Supervisor 一个 goroutine 调用）。审计与观察者通知交给
// Control Lane 事后补：它们会格式化/调用外部代码，不该发生在这条同步路径上。
func (m *Module) RevokeAll(epoch uint64) {
	m.revokeSeq.Add(1) // odd: 禁止 Acquire 发布
	m.markSafetyFloor(epoch)
	index := m.slots.Load()
	for _, slot := range index.all {
		old := slot.cur.Swap(nil)
		if old == nil {
			continue
		}
		slot.revokedEpoch.Store(epoch)
		// Acquire 不允许在 revoked 非空时发布，因此 CAS 失败只可能是内部不变量
		// 已被破坏。保持旧事件比覆盖它更安全；正常运行不会走到该分支。
		m.revPending.Add(1)
		if slot.revoked.CompareAndSwap(nil, old) {
			continue
		}
		m.revPending.Add(^uint64(0))
	}
	m.revokeSeq.Add(1) // even: 撤销事件已全部发布
}

func (m *Module) markSafetyFloor(epoch uint64) {
	for {
		floor := m.safetyFloor.Load()
		if epoch <= floor || m.safetyFloor.CompareAndSwap(floor, epoch) {
			return
		}
	}
}

// Check 是派发前的控制权复核，返回可放进 ExecutionContext 的当前 motion epoch
//
// 无锁、零堆分配：每条运动命令走一次（由 AllocsPerRun 测试守住）。
// 它复核 里属于本模块的那几条前置：有效租约 + Safety NORMAL + epoch 未过期 +
// deadline 未到 + deadman 新鲜。sequence 与单条命令的 deadline 属于调用侧
func (m *Module) Check(id ID, conn ConnID) (uint64, error) {
	_, l, err := m.lookup(id, conn, time.Now())
	if err != nil {
		return 0, err
	}
	return l.Epoch, nil
}

// CheckResource is the Method Gate query: it proves that conn currently owns a
// valid lease for exactly resource without exposing or guessing the internal
// 128-bit lease ID. The second lookup closes the race where the slot changes
// after the first atomic load.
func (m *Module) CheckResource(
	conn ConnID,
	resource string,
	resourceGeneration uint64,
) (uint64, error) {
	slot := m.slot(resource)
	if slot == nil {
		return 0, ErrControlNotHeld
	}
	l := slot.cur.Load()
	if l == nil || l.Conn != conn || l.Resource != resource ||
		l.ResourceGeneration != resourceGeneration {
		return 0, ErrControlNotHeld
	}
	if err := m.validateCurrent(slot, l, time.Now()); err != nil {
		return 0, err
	}
	return l.Epoch, nil
}

// ControlSnapshot 返回 legacy base.main 的控制面一致只读快照。其它 Resource 使用
// ControlSnapshotFor；保留无参方法是为了不改变 health 的既有窄接口。
func (m *Module) ControlSnapshot() Snapshot {
	return m.ControlSnapshotFor(ResourceBaseMain)
}

// ControlSnapshotFor 返回指定 Resource 的一致只读快照。
//
// Gate 在读槽前后各采样一次；只有两次完全相同才返回，避免 Trip/re-arm 插在中间时
// 报出过时的 NORMAL/Held。Lease.Epoch 是资源 token，允许小于 Snapshot.Epoch。
func (m *Module) ControlSnapshotFor(resource string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	for {
		seq := m.revokeSeq.Load()
		if seq&1 != 0 {
			continue
		}
		st, ep := m.gate.Snapshot()
		s := Snapshot{State: st, Epoch: ep}
		slot := m.slot(resource)
		var l *Lease
		if slot != nil {
			l = slot.cur.Load()
		}
		stAfter, epAfter := m.gate.Snapshot()
		if st != stAfter || ep != epAfter || m.revokeSeq.Load() != seq {
			continue
		}

		if st != motiongate.StateNormal {
			s.Source = SourceSafety
			return s
		}
		if l == nil || m.leaseStateAt(slot, l, st, ep, time.Now()) != nil {
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
}

// lookup 取出与 (id, conn) 匹配且此刻仍然有效的租约
//
// 无锁、零堆分配：只读原子量，返回的错误全是预分配哨兵
func (m *Module) lookup(id ID, conn ConnID, now time.Time) (*resourceSlot, *Lease, error) {
	slot, l := m.findLease(id, conn)
	if l == nil {
		return nil, nil, ErrControlNotHeld
	}
	if err := m.validateCurrent(slot, l, now); err != nil {
		return nil, nil, err
	}
	return slot, l, nil
}

// validateCurrent checks both lease state and slot membership. The second slot
// read closes the common race where a normal release/revoke removes l after
// findLease loaded it but before validation completed. A renewal replaces the
// immutable pointer while preserving lease identity, so membership compares
// the stable ID/connection/resource tuple rather than pointer identity.
func (m *Module) validateCurrent(slot *resourceSlot, l *Lease, now time.Time) error {
	if err := m.leaseState(slot, l, now); err != nil {
		return err
	}
	if !slotHolds(slot, l) {
		return ErrControlNotHeld
	}
	return nil
}

func slotHolds(slot *resourceSlot, lease *Lease) bool {
	if slot == nil || lease == nil {
		return false
	}
	current := slot.cur.Load()
	return current != nil && current.ID == lease.ID && current.Conn == lease.Conn &&
		current.Resource == lease.Resource
}

// leaseState 复核一条租约此刻是否仍能授权运动，nil 表示有效。读一次 Gate 后转交
// leaseStateAt。
func (m *Module) leaseState(slot *resourceSlot, l *Lease, now time.Time) error {
	st, ep := m.gate.Snapshot()
	return m.leaseStateAt(slot, l, st, ep, now)
}

// leaseStateAt 用已经读好的(st, ep) 复核租约有效性，让调用方能把一次 Gate 读同时
// 用于别的判定（见 ControlSnapshot），避免同一逻辑里读两次 Gate 产生撕裂。
//
// 顺序即优先级：Safety > epoch > deadline > deadman。先报最根本的原因，调用者据此
// 决定是重新申请还是等 re-arm。
func (m *Module) leaseStateAt(slot *resourceSlot, l *Lease, st motiongate.State, _ uint64, now time.Time) error {
	if st != motiongate.StateNormal {
		return ErrSafetyLatched
	}
	// motion epoch 由全局单调分配器铸造，但普通边界只撤目标 Resource；其它槽保留
	// 自己较早的 token。Safety floor 才是跨 Resource 的全局撤销边界。
	if l.Epoch <= m.safetyFloor.Load() {
		return ErrStaleEpoch
	}
	if now.After(l.Deadline) {
		return ErrLeaseExpired
	}
	if l.Deadman > 0 && now.Sub(m.base)-time.Duration(slot.fresh.Load()) > l.Deadman {
		return ErrDeadmanExpired
	}
	return nil
}

// markFresh 在指定 Resource 槽记录一次新鲜输入，存相对单调基准的纳秒。
//
// 只增不减（原子 max）：单调时钟下更晚的调用总是更大的值，因此这只会挡住一个晚提交的
// 旧调用把新鲜度倒写回去 - 正是要防的竞态：两个并发 Refresh 里较早那次晚落地时，
// 若无条件 Store 会把 freshness 从约 20ms 打回 0，令有效租约提前 deadman。零堆分配。
func (m *Module) markFresh(slot *resourceSlot, now time.Time) {
	v := int64(now.Sub(m.base))
	for {
		cur := slot.fresh.Load()
		if v <= cur {
			return
		}
		if slot.fresh.CompareAndSwap(cur, v) {
			return
		}
	}
}

// dropLocked 撤下一条租约并递增 epoch。调用方必须持有 mu
//
// 用 CAS 而不是无条件 Store(nil)：CAS 失败说明这条租约已经被别的路径收走了 - 通常
// 是 RevokeAll（safety 的 RT 路径，不取 mu，因此能与本函数交错）。那条边界的 epoch
// 已由 gate.Trip 递增、审计也由 Lane 的撤销记账路径补，这里必须安静退出，否则会多
// 记出重复审计。
//
// 递增用 BumpEpochIfNormal 而不是无条件 BumpEpoch：若 Gate 已被 Trip 锁存（而 RevokeAll
// 尚未把这条租约 Swap 走，CAS 仍成功），无条件递增会把已锁存的 Gate 又推进一代，令
// Safety 的投递/跟踪 epoch 错开。锁存时那条撤销边界已被 Trip 的递增涵盖，这里不再叠加。
func (m *Module) dropLocked(slot *resourceSlot, l *Lease, action string, cause error) {
	if !slot.cur.CompareAndSwap(l, nil) {
		return
	}
	_, _ = m.advanceEpochLocked()
	m.notifyLeaseEnded(l)
	m.recordLease(action, l, cause)
}

// dropMatchingLocked 原子摘除所有匹配槽，并把这一批普通撤权记为一个全局 motion
// epoch 边界。调用方必须持有 mu。Safety 并发收走的槽由 RevokeAll 自己通知，不重复记账。
func (m *Module) dropMatchingLocked(match func(*Lease) bool, action string, cause error) {
	index := m.slots.Load()
	dropped := make([]*Lease, 0)
	for _, slot := range index.all {
		l := slot.cur.Load()
		if l == nil || !match(l) || !slot.cur.CompareAndSwap(l, nil) {
			continue
		}
		dropped = append(dropped, l)
	}
	if len(dropped) == 0 {
		return
	}
	_, _ = m.advanceEpochLocked()
	for _, l := range dropped {
		m.notifyLeaseEnded(l)
		m.recordLease(action, l, cause)
	}
}

// advanceEpochLocked 从全局 motion epoch 分配器取下一个单调 token。普通租约边界只
// 改目标 Resource，绝不静默改写其它有效 lease 的 token；跨 Resource 撤销只属于 Safety。
func (m *Module) advanceEpochLocked() (uint64, bool) {
	return m.gate.BumpEpochIfNormal()
}

func (m *Module) findLease(id ID, conn ConnID) (*resourceSlot, *Lease) {
	for _, slot := range m.slots.Load().all {
		l := slot.cur.Load()
		if l != nil && l.ID == id && l.Conn == conn {
			return slot, l
		}
	}
	return nil, nil
}

func (m *Module) slot(resource string) *resourceSlot {
	return m.slots.Load().byResource[resource]
}

// slotLocked 返回现有槽，或在 mu 下 copy-on-write 发布一个新槽。槽永不删除，保证
// RevokeAll 读到的不可变快照及其中指针在整个进程生命周期内有效。
func (m *Module) slotLocked(resource string) *resourceSlot {
	current := m.slots.Load()
	if slot := current.byResource[resource]; slot != nil {
		return slot
	}
	if len(current.all) >= maxResourceSlots {
		return nil
	}
	slot := &resourceSlot{resource: resource}
	byResource := make(map[string]*resourceSlot, len(current.byResource)+1)
	for handle, existing := range current.byResource {
		byResource[handle] = existing
	}
	byResource[resource] = slot
	all := make([]*resourceSlot, len(current.all)+1)
	copy(all, current.all)
	all[len(current.all)] = slot
	m.slots.Store(&slotIndex{byResource: byResource, all: all})
	return slot
}

func (m *Module) current(resource string) *Lease {
	if slot := m.slot(resource); slot != nil {
		return slot.cur.Load()
	}
	return nil
}
