// 本文件把 control 接入 kernel.Module 生命周期, 持有按 Resource 隔离的租约槽与
// Control Lane, 并集中全部审计写入. 租约状态机本身在 slot.go, 到期检测循环在 lane.go
package control

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/motiongate"
	"github.com/nervus-os/nervud/internal/scheduler"
)

// laneTick 是 Control Lane 检查 deadline/deadman 到期的节拍
//
// 10ms 对 HUMAN 的 300ms deadman 约是 3% 的分辨率, 够用; 空闲 (无租约) 时 onTick
// 只扫描不可变槽快照并做每槽原子 Load, 不取 control 变更锁.
const laneTick = 10 * time.Millisecond

// maxResourceSlots is a hard upper bound on every Safety and Control Lane
// scan. Slots intentionally survive catalog removal so RevokeAll can retain a
// lock-free immutable snapshot; without a bound, repeated handle churn could
// make the real-time path grow for the lifetime of the process.
const maxResourceSlots = 1024

// laneExitTimeout 是 Stop 等 Control Lane 退出的上限 (见 Module.Stop 的顺序说明)
const laneExitTimeout = 500 * time.Millisecond

// LaneSpawner 是 control 需要的 scheduler 窄接口 (消费者定义, *scheduler.Scheduler
// 隐式满足). 与 safety.LaneSpawner 形状相同但各自定义 - 两个模块各自只声明自己要
// 的那一个方法, 比共享一个接口更能约束依赖面
type LaneSpawner interface {
	SpawnDedicated(name string, policy scheduler.Policy, priority int, fn func(context.Context)) error
}

// LeaseObserver receives the terminal boundary of an effective ControlLease.
//
// The callback runs only after the lease has been removed from the authoritative
// slot. It may run on the Control Lane, a control-plane caller, or Stop, so the
// implementation must be concurrency-safe and return promptly. RevokeAll never
// invokes it on the Safety Supervisor Lane; that path is deferred to
// drainRevoked so the RT path remains lock-free, allocation-free, and
// non-blocking.
type LeaseObserver interface {
	ControlLeaseEnded(conn ConnID, resource string, leaseID ID)
}

type leaseObserverHolder struct {
	observer LeaseObserver
}

// resourceSlot 是一个 Resource 的 exclusive_control 槽. 槽对象一经创建就不再删除,
// 因而 slots 快照与 Safety RevokeAll 可以长期持有它的稳定指针.
type resourceSlot struct {
	resource string
	cur      atomic.Pointer[Lease]
	fresh    atomic.Int64

	// Safety 路径只把被撤租约发布到这里; 审计与观察者通知由普通优先级路径排空.
	// Acquire 在同一 Resource 再次发布前必先排空, 因此每个槽只需一个待处理位置.
	revoked      atomic.Pointer[Lease]
	revokedEpoch atomic.Uint64
}

// slotIndex 是不可变的 Resource -> slot 索引. 新增 Resource 时在 mu 下 copy-on-write;
// 读侧和 RevokeAll 只原子读取快照, 不碰 Go map 的并发写.
type slotIndex struct {
	byResource map[string]*resourceSlot
	all        []*resourceSlot
}

// Module 把 control 接入 kernel.Module + kernel.FatalReporter, 并实现 safety 侧的
// LeaseRevoker (RevokeAll)
type Module struct {
	spawner LaneSpawner
	gate    *motiongate.Gate
	aud     audit.Recorder
	log     *slog.Logger
	policy  Policy

	// slots 按已解析的稳定 Resource handle 隔离 exclusive_control. 索引不可变;
	// 槽内 cur/fresh 独立, 因此不同 Resource 可并行持有且 deadman 互不续命.
	slots atomic.Pointer[slotIndex]

	// mu 只序列化 control 自己的变更路径. RevokeAll 绝不取它 - 它跑在 safety 的
	// Supervisor Lane (FIFO 90) 上, 等普通优先级的持锁者就是优先级反转
	mu sync.Mutex

	// base 是所有槽共享的单调时钟基准; 每个槽的 fresh 保存距 base 的纳秒.
	base time.Time

	// RevokeAll 用奇偶 seqlock 包住整次无锁清槽. Acquire 只有在读到相同偶数值时
	// 才能发布新租约, 封住 Safety 正在发布待通知撤租时重获同 Resource 的竞态.
	revokeSeq   atomic.Uint64
	safetyFloor atomic.Uint64
	revPending  atomic.Uint64
	revDrainMu  sync.Mutex

	observer atomic.Pointer[leaseObserverHolder]

	// laneWG 计 Control Lane 的在跑数; Stop 用它把Lane 已退出排在最终撤租/排空
	// 之前, 避免 Lane 退出后 Stop 又签不掉, 或 drain 与 Lane 并发消费环
	laneWG sync.WaitGroup

	stopCh   chan struct{}
	stopOnce sync.Once
	fatal    chan error
}

// New 构造 control.Module
//
// gate 必须是 main.go 里 motiongate.New 出来的同一个实例. safety 与 control
// 共用它, 才能原子观察同一份锁存状态和 epoch
func New(spawner LaneSpawner, gate *motiongate.Gate, aud audit.Recorder, log *slog.Logger, policy Policy) *Module {
	base := &resourceSlot{resource: ResourceBaseMain}
	index := &slotIndex{
		byResource: map[string]*resourceSlot{ResourceBaseMain: base},
		all:        []*resourceSlot{base},
	}
	m := &Module{
		spawner: spawner,
		gate:    gate,
		aud:     aud,
		log:     log,
		policy:  policy,
		base:    time.Now(),
		stopCh:  make(chan struct{}),
		fatal:   make(chan error, 1),
	}
	m.slots.Store(index)
	return m
}

func (m *Module) Name() string { return "control" }

// SetLeaseObserver installs the lifecycle observer used to invalidate data-plane
// state derived from a ControlLease. Passing nil removes the observer. Replacing
// it is atomic and is safe before or during Module operation.
func (m *Module) SetLeaseObserver(observer LeaseObserver) {
	if observer == nil {
		m.observer.Store(nil)
		return
	}
	m.observer.Store(&leaseObserverHolder{observer: observer})
}

func (m *Module) notifyLeaseEnded(l *Lease) {
	if holder := m.observer.Load(); holder != nil {
		holder.observer.ControlLeaseEnded(l.Conn, l.Resource, l.ID)
	}
}

// Start 校验 Policy 后起 Control Lane
//
// SpawnDedicated 是同步握手. 生产环境设不上 RT 优先级时 Start 必须返回错误,
// 因为在没有时序保证的线程上运行 Control Lane 会制造虚假的安全承诺
func (m *Module) Start(_ context.Context) error {
	if err := m.policy.Validate(); err != nil {
		return fmt.Errorf("control: invalid policy: %w", err)
	}
	// laneWG.Add 必须 happen-before laneFn 里的 Done, 故在 spawn 前 Add, 失败即回退.
	// SpawnDedicated 返回 nil 时 fn 一定会运行, 因此 Add/Done 恰好配对
	m.laneWG.Add(1)
	if err := m.spawner.SpawnDedicated("control",
		scheduler.PolicyRR, scheduler.PrioControl,
		m.laneFn("control", m.runLane)); err != nil {
		m.laneWG.Done()
		return fmt.Errorf("control: start control lane: %w", err)
	}
	if m.log != nil {
		m.log.Info("control: ready", "prio", scheduler.PrioControl,
			"human_ttl", m.policy.Human.TTL, "human_deadman", m.policy.Human.Deadman,
			"ai_ttl", m.policy.AI.TTL)
	}
	return nil
}

// Stop 停掉 Lane 并撤销残留租约
//
// 停机后不留任何控制权: 要求新 Host session 从 NONE 开始, 不恢复旧 Lease.
// 这里主动撤一次并递增 epoch, 让已经进入 Provider 队列的旧命令在进程退出前就失效,
// 不依赖下次启动时 epoch 恰好不同.
//
// 顺序: 先关 stopCh 让 Lane 退出, 等它真正退出 (waitLanes), 再做最终排空与撤租.
// 这道序保证Lane 已停先于Stop 消费撤销环, 二者不并发消费同一个环; 也保证
// 停机后不会再有 Lane 在跑到期检测. Acquire 侧靠 stopCh 拒绝新签发 (见 Acquire).
func (m *Module) Stop(_ context.Context) error {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		m.waitLanes(laneExitTimeout)
	})

	m.mu.Lock()
	defer m.mu.Unlock()
	m.drainRevoked()
	m.dropMatchingLocked(func(*Lease) bool { return true }, actionRevoked, ErrShuttingDown)
	return nil
}

// waitLanes 等 Control Lane 退出, 最多等 d. 超时即放弃并告警 - 一条卡死的 Lane 不能
// 拖垮整条关闭序列 (kernel 另有单模块 Stop 5s 上限兜底).
func (m *Module) waitLanes(d time.Duration) {
	done := make(chan struct{})
	go func() {
		m.laneWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		if m.log != nil {
			m.log.Warn("control: lane did not exit before shutdown drain", "timeout", d)
		}
	}
}

// stopping 报告模块是否已进入停机 (stopCh 已关). Acquire 在持 mu 时据此拒绝新签发.
func (m *Module) stopping() bool {
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

// Fatal 实现 kernel.FatalReporter: Control Lane 在 stopCh 未关时退出即上报致命错误
func (m *Module) Fatal() <-chan error { return m.fatal }

// laneFn 包裹 Lane 主体, 把未经 Stop 就退出识别为结构性故障并上报 Fatal
//
//	(与 safety.Module.laneFn 同一形状)
func (m *Module) laneFn(name string, body func(context.Context)) func(context.Context) {
	return func(ctx context.Context) {
		// laneWG.Add 在 Start 里 (spawn 成功后) 做, 这里只 Done. 放 goroutine 内 Add
		// 会有 Start -> Stop 立即竞态: Stop 的 Wait 可能在 fn 尚未开跑时就返回
		defer m.laneWG.Done()

		body(ctx)
		select {
		case <-m.stopCh:
			return // 正常: 模块 Stop 已关 stopCh
		default:
		}
		select {
		case m.fatal <- fmt.Errorf("control: lane %q exited unexpectedly", name):
		default:
		}
	}
}

// 审计 Action 名. 集中定义避免各处拼字符串拼歪, 离线规则按 "control.<Action>" 匹配
const (
	actionGranted        = "LeaseGranted"
	actionRenewed        = "LeaseRenewed"
	actionReleased       = "LeaseReleased"
	actionPreempted      = "LeasePreempted"
	actionExpired        = "LeaseExpired"
	actionDeadmanExpired = "LeaseDeadmanExpired"
	actionRevoked        = "LeaseRevoked"
	actionDenied         = "LeaseDenied"
)

// recordLease 记一条与具体租约相关的审计
//
// cause 非 nil 即置 Denied: 让离线规则能一眼筛出非正常结束的控制会话 (到期,
// deadman 失效, 被 Safety 撤销), 与正常的签发/续租/释放分开. 同 safety.recordEvent
func (m *Module) recordLease(action string, l *Lease, cause error) {
	m.aud.Record(context.Background(), audit.Event{
		Action:  "control." + action,
		Subject: l.Owner.String(),
		Denied:  cause != nil,
		Err:     cause,
		Detail: fmt.Sprintf("lease=%s class=%s resource=%s epoch=%d",
			l.ID, l.Class, l.Resource, l.Epoch),
	})
}

// recordDenied 记一条被拒绝的申请. 此时还没有租约, 归因用申请方自己的身份
func (m *Module) recordDenied(req Request, cause error) {
	m.aud.Record(context.Background(), audit.Event{
		Action:  "control." + actionDenied,
		Subject: req.Owner.String(),
		Denied:  true,
		Err:     cause,
		Detail: fmt.Sprintf("class=%s resource=%s conn=%d",
			req.Class, req.Resource, req.Conn),
	})
}
