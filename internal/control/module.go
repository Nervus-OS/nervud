// 本文件把 control 接入 kernel.Module 生命周期，持有唯一的租约槽与 Control Lane，
// 并集中全部审计写入。租约状态机本身在 slot.go，到期检测循环在 lane.go
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
// 10ms 对 HUMAN 的 300ms deadman 约是 3% 的分辨率，够用；空闲（无租约）时 onTick
// 只做一次原子 Load 就返回，代价可忽略
const laneTick = 10 * time.Millisecond

// laneExitTimeout 是 Stop 等 Control Lane 退出的上限（见 Module.Stop 的顺序说明）
const laneExitTimeout = 500 * time.Millisecond

// LaneSpawner 是 control 需要的 scheduler 窄接口（消费者定义、*scheduler.Scheduler
// 隐式满足）。与 safety.LaneSpawner 形状相同但各自定义 - 两个模块各自只声明自己要
// 的那一个方法，比共享一个接口更能约束依赖面
type LaneSpawner interface {
	SpawnDedicated(name string, policy scheduler.Policy, priority int, fn func(context.Context)) error
}

// Module 把 control 接入 kernel.Module + kernel.FatalReporter，并实现 safety 侧的
// LeaseRevoker（RevokeAll）
type Module struct {
	spawner LaneSpawner
	gate    *motiongate.Gate
	aud     audit.Recorder
	log     *slog.Logger
	policy  Policy

	// cur 是唯一的租约槽（v1 单 Resource base.main 的 exclusive_control）。
	// nil = NONE。读侧无锁；写侧除 RevokeAll 外都由 mu 串行化
	cur atomic.Pointer[Lease]

	// mu 只序列化 control 自己的变更路径。RevokeAll 绝不取它 - 它跑在 safety 的
	// Supervisor Lane（FIFO 90）上，等普通优先级的持锁者就是优先级反转
	mu sync.Mutex

	// base 是单调时钟基准；fresh 记最近一次新鲜输入距 base 的纳秒。
	// 用相对值而不是 time.Time 是为了能放进 atomic.Int64：deadman 刷新在每条运动
	// 命令上发生，不能为它重建不可变 Lease。fresh 只增不减（markFresh 做原子 max），
	// 防止一个晚到的旧调用把新鲜度倒写回去
	base  time.Time
	fresh atomic.Int64

	// 被 Safety 撤销的租约交给 Control Lane 事后补审计的定长环。
	// 生产者只有一个（RevokeAll，跑在 safety Supervisor Lane / FIFO 90 上），因此
	// revHead 无需 CAS；消费者是 Control Lane（运行期）与 Stop（Lane 退出后），二者
	// 由生命周期序列化，不并发。用并行原子数组 + 环而不是单指针槽：
	//  - 零堆分配：RevokeAll 只做原子写，绝不 new（由 alloc 测试守住）
	//  - 不丢事件：单槽在撤销 A -> rearm -> 取 B -> 撤销 B快过一次 drain 时会丢 A
	//  - 不串 epoch：lease 与它的 halt epoch 存在同一格，不会像两个独立槽那样错配
	revLease   [revokedRingSize]atomic.Pointer[Lease]
	revEpoch   [revokedRingSize]atomic.Uint64
	revHead    atomic.Uint64 // 生产者写位置（只由 RevokeAll 递增）
	revTail    atomic.Uint64 // 消费者读位置（只由 drainRevoked 递增）
	revDropped atomic.Uint64 // 环满丢弃计数（审计降级，极少见）

	// laneWG 计 Control Lane 的在跑数；Stop 用它把Lane 已退出排在最终撤租/排空
	// 之前，避免 Lane 退出后 Stop 又签不掉、或 drain 与 Lane 并发消费环
	laneWG sync.WaitGroup

	stopCh   chan struct{}
	stopOnce sync.Once
	fatal    chan error
}

// revokedRingSize 是被撤租约待记账环的容量（2 的幂）。足够吸收一次停机风暴里的多轮
// 撤销；满则丢弃并计数。
const revokedRingSize = 16

// New 构造 control.Module
//
// gate 必须是 main.go 里 motiongate.New 出来的同一个实例。safety 与 control
// 共用它，才能原子观察同一份锁存状态和 epoch
func New(spawner LaneSpawner, gate *motiongate.Gate, aud audit.Recorder, log *slog.Logger, policy Policy) *Module {
	return &Module{
		spawner: spawner,
		gate:    gate,
		aud:     aud,
		log:     log,
		policy:  policy,
		base:    time.Now(),
		stopCh:  make(chan struct{}),
		fatal:   make(chan error, 1),
	}
}

func (m *Module) Name() string { return "control" }

// Start 校验 Policy 后起 Control Lane
//
// SpawnDedicated 是同步握手。生产环境设不上 RT 优先级时 Start 必须返回错误，
// 因为在没有时序保证的线程上运行 Control Lane 会制造虚假的安全承诺
func (m *Module) Start(_ context.Context) error {
	if err := m.policy.Validate(); err != nil {
		return fmt.Errorf("control: invalid policy: %w", err)
	}
	// laneWG.Add 必须 happen-before laneFn 里的 Done，故在 spawn 前 Add、失败即回退。
	// SpawnDedicated 返回 nil 时 fn 一定会运行，因此 Add/Done 恰好配对
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
// 停机后不留任何控制权： 要求新 Host session 从 NONE 开始、不恢复旧 Lease。
// 这里主动撤一次并递增 epoch，让已经进入 Provider 队列的旧命令在进程退出前就失效，
// 不依赖下次启动时 epoch 恰好不同。
//
// 顺序：先关 stopCh 让 Lane 退出，等它真正退出（waitLanes），再做最终排空与撤租。
// 这道序保证Lane 已停先于Stop 消费撤销环，二者不并发消费同一个环；也保证
// 停机后不会再有 Lane 在跑到期检测。Acquire 侧靠 stopCh 拒绝新签发（见 Acquire）。
func (m *Module) Stop(_ context.Context) error {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		m.waitLanes(laneExitTimeout)
	})

	m.mu.Lock()
	defer m.mu.Unlock()
	m.drainRevoked()
	if l := m.cur.Load(); l != nil {
		m.dropLocked(l, actionRevoked, ErrShuttingDown)
	}
	return nil
}

// waitLanes 等 Control Lane 退出，最多等 d。超时即放弃并告警 - 一条卡死的 Lane 不能
// 拖垮整条关闭序列（kernel 另有单模块 Stop 5s 上限兜底）。
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

// stopping 报告模块是否已进入停机（stopCh 已关）。Acquire 在持 mu 时据此拒绝新签发。
func (m *Module) stopping() bool {
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

// Fatal 实现 kernel.FatalReporter：Control Lane 在 stopCh 未关时退出即上报致命错误
func (m *Module) Fatal() <-chan error { return m.fatal }

// laneFn 包裹 Lane 主体，把未经 Stop 就退出识别为结构性故障并上报 Fatal
// （与 safety.Module.laneFn 同一形状）
func (m *Module) laneFn(name string, body func(context.Context)) func(context.Context) {
	return func(ctx context.Context) {
		// laneWG.Add 在 Start 里（spawn 成功后）做，这里只 Done。放 goroutine 内 Add
		// 会有 Start -> Stop 立即竞态：Stop 的 Wait 可能在 fn 尚未开跑时就返回
		defer m.laneWG.Done()

		body(ctx)
		select {
		case <-m.stopCh:
			return // 正常：模块 Stop 已关 stopCh
		default:
		}
		select {
		case m.fatal <- fmt.Errorf("control: lane %q exited unexpectedly", name):
		default:
		}
	}
}

// 审计 Action 名。集中定义避免各处拼字符串拼歪，离线规则按 "control.<Action>" 匹配
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
// cause 非 nil 即置 Denied：让离线规则能一眼筛出非正常结束的控制会话（到期、
// deadman 失效、被 Safety 撤销），与正常的签发/续租/释放分开。同 safety.recordEvent
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

// recordDenied 记一条被拒绝的申请。此时还没有租约，归因用申请方自己的身份
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
