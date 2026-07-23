// 见 doc.go 的包说明。
//
// 本文件把 safety 接入 kernel.Module 生命周期，持有两条 RT Lane（Stop / Supervisor）
// 与普通优先级的审计排空 goroutine，并对外提供 Observer / Controller 面。
package safety

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

const (
	// auditRingSize 审计 ring 容量（2 的幂）。足够吸收一次停机风暴的固定事件；满则丢弃计数。
	auditRingSize = 256
	// superTick Supervisor 检查超时预算的节拍。10ms 给 100ms 级预算约 10% 分辨率；
	// 空闲（未锁存）时 onTick 立即返回，代价可忽略。
	superTick = 10 * time.Millisecond
	// drainInterval auditDrain 轮询 ring 的间隔。审计非实时，20ms 延迟可接受。
	drainInterval = 20 * time.Millisecond
	// stopDrainTimeout Stop() 等待 auditDrain 收尾落盘的上限。
	stopDrainTimeout = 500 * time.Millisecond
	// laneExitTimeout Stop() 等两条 RT Lane 退出的上限（见 Module.Stop 的顺序说明）。
	laneExitTimeout = 500 * time.Millisecond
)

// LaneSpawner 是 safety 需要的 scheduler 窄接口（消费者定义、*scheduler.Scheduler 隐式满足）。
type LaneSpawner interface {
	SpawnDedicated(name string, policy scheduler.Policy, priority int, fn func(context.Context)) error
}

// LeaseRevoker 是 control 落地后清理执行器 lease 对象/发 EndpointRevoked 的窄接口
// （消费者定义）。v1 可为 nil：motion epoch 递增已是主撤销手段。
type LeaseRevoker interface {
	RevokeAll(epoch uint64)
}

// Module 把 safety 接入 kernel.Module + kernel.FatalReporter，并实现 Observer / Controller。
type Module struct {
	spawner  LaneSpawner
	gate     *motiongate.Gate
	aud      audit.Recorder
	log      *slog.Logger
	contract Contract
	path     SafetyPath
	src      StopProgressSource

	// 触发热路径（全部预分配）。
	pendingReason atomic.Uint32 // 最新触发原因，供 Stop Lane 读取
	phase         atomic.Uint64 // [当前 StopPhase | 它所属的 halt epoch]，见 packPhase
	wake          chan struct{} // 唤醒 Stop Lane（cap 1）
	superWake     chan struct{} // 唤醒 Supervisor（cap 1）

	ring *auditRing  // MPSC：Stop Lane + Supervisor 生产，auditDrain 消费
	sup  *supervisor // 只在 Supervisor goroutine 内访问

	// 生命周期。
	stopCh   chan struct{}
	stopOnce sync.Once
	fatal    chan error // cap 1，FatalReporter

	// laneWG 计两条 RT Lane 的在跑数；Stop 用它把「Lane 已退出」排在「审计收尾」
	// 之前。没有这道序，Lane 可能在最后一次排空之后还往 ring 里写，那些事件就永远
	// 落不了盘——恰恰是停机期间最该被看见的一类
	laneWG sync.WaitGroup

	// drainStop 由 Stop 在 Lane 全部退出后关闭，驱动 auditDrain 做最后一次排空。
	// 它与 stopCh 分开，正是为了表达这个先后关系
	drainStop chan struct{}
	drainDone chan struct{}
}

// New 构造 safety.Module。全部依赖以窄接口/值注入（装配范式见 pkgregistry/module.go）。
// gate 由 main.go 用 motiongate.New() 构造一次，并注入 safety 与（将来）control 同一实例。
// revoker 可为 nil。
func New(
	spawner LaneSpawner,
	gate *motiongate.Gate,
	aud audit.Recorder,
	log *slog.Logger,
	contract Contract,
	path SafetyPath,
	src StopProgressSource,
	revoker LeaseRevoker,
) *Module {
	m := &Module{
		spawner:   spawner,
		gate:      gate,
		aud:       aud,
		log:       log,
		contract:  contract,
		path:      path,
		src:       src,
		wake:      make(chan struct{}, 1),
		superWake: make(chan struct{}, 1),
		ring:      newAuditRing(auditRingSize),
		stopCh:    make(chan struct{}),
		fatal:     make(chan error, 1),
		drainStop: make(chan struct{}),
		drainDone: make(chan struct{}),
	}
	m.phase.Store(packPhase(PhaseUnspecified, 0))
	m.sup = &supervisor{
		gate:     gate,
		ring:     m.ring,
		contract: contract,
		revoker:  revoker,
		phase:    &m.phase,
		pending:  &m.pendingReason,
	}
	return m
}

func (m *Module) Name() string { return "safety" }

// Start 校验 Contract 后起两条 RT Lane 与审计排空 goroutine。
//
// SpawnDedicated 是同步握手：生产环境设不上 RT 优先级即返回 error → Start 返回 error →
// 内核 fail-fast（README「生产环境实时优先级设置失败 = fatal」）。对外开门（IPC）之前
// Safety 必须就绪，因此本模块在 IPC 之前注册。
func (m *Module) Start(_ context.Context) error {
	if err := m.contract.Validate(); err != nil {
		return fmt.Errorf("safety: invalid contract: %w", err)
	}
	// laneWG.Add 必须 happen-before 对应的 Done（在 laneFn 里），因此在 spawn 前 Add；
	// spawn 失败即回退计数。SpawnDedicated 返回 nil ⟺ fn 一定会被调用（scheduler 语义），
	// 于是 Add 与 Done 恰好配对
	m.laneWG.Add(1)
	if err := m.spawner.SpawnDedicated("safety-stop",
		scheduler.PolicyFIFO, scheduler.PrioSafetyLatch,
		m.laneFn("safety-stop", m.runStopLane)); err != nil {
		m.laneWG.Done()
		return fmt.Errorf("safety: start stop lane: %w", err)
	}
	m.laneWG.Add(1)
	if err := m.spawner.SpawnDedicated("safety-supervisor",
		scheduler.PolicyFIFO, scheduler.PrioSafety,
		m.laneFn("safety-supervisor", m.runSupervisor)); err != nil {
		m.laneWG.Done()
		return fmt.Errorf("safety: start supervisor lane: %w", err)
	}
	go m.runAuditDrain()
	if m.log != nil {
		m.log.Info("safety: armed", "stop_prio", scheduler.PrioSafetyLatch, "supervisor_prio", scheduler.PrioSafety)
	}
	return nil
}

// Stop 分两拍收尾：先让两条 RT Lane 退出，再让 auditDrain 做最后一次排空。
//
// 顺序是有意义的。Scheduler 对 Lane 的 join 发生在【所有模块 Stop 之后】
// （sched.Shutdown），只靠它的话，本模块的审计排空早已结束，而 Stop Lane 可能还在
// 投递并继续往 ring 里写——那些事件没有任何人再读，直接丢失。因此这里自己等一次
// 自己的 Lane：等到（或超时放弃）之后才关 drainStop。
//
// 两段等待都有上限：一条卡死的 Lane 不能拖垮整条关闭序列（kernel 对单模块 Stop
// 另有 5s 上限兜底）。超时即放弃并告警，退回到「可能少记几条」的旧行为。
func (m *Module) Stop(_ context.Context) error {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		m.waitLanes(laneExitTimeout)
		close(m.drainStop)
	})
	select {
	case <-m.drainDone:
	case <-time.After(stopDrainTimeout):
	}
	return nil
}

// waitLanes 等本模块的 RT Lane 退出，最多等 d
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
			m.log.Warn("safety: lanes did not exit before audit drain closed; some events may be lost",
				"timeout", d)
		}
	}
}

// Fatal 实现 kernel.FatalReporter：任一 Lane 在 stopCh 未关时退出（异常或关闭序被打乱）
// 即上报致命错误，触发内核反序关停、非零退出、systemd 重启（MCU 心跳兜底）。
func (m *Module) Fatal() <-chan error { return m.fatal }

// laneFn 包裹 Lane 主体，把「未经 Stop 就退出」识别为结构性故障并上报 Fatal。
func (m *Module) laneFn(name string, body func(context.Context)) func(context.Context) {
	return func(ctx context.Context) {
		// laneWG 的 Add 在 Start 里、SpawnDedicated 成功之后做（那时才保证 fn 会跑），
		// 这里只负责 Done。放在 goroutine 内 Add 会有 Start→Stop 立即竞态：Stop 的
		// Wait 可能在 fn 尚未开跑、计数还是 0 时就返回
		defer m.laneWG.Done()

		body(ctx)
		select {
		case <-m.stopCh:
			return // 正常：模块 Stop 已关 stopCh
		default:
		}
		select {
		case m.fatal <- fmt.Errorf("safety: lane %q exited unexpectedly", name):
		default:
		}
	}
}

// runSupervisor 是 Supervisor Lane（FIFO 90）的循环：只在有界 channel/ticker 上等待，
// 不做任意 I/O。superWake 来自 Trip/re-arm；reports 来自 Provider；ticker 驱动超时检查。
func (m *Module) runSupervisor(ctx context.Context) {
	reports := m.src.Reports() // 只取一次；stub 返回 nil channel（该分支永不触发）
	ticker := time.NewTicker(superTick)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-m.superWake:
			m.sup.reconcile(time.Now())
		case r := <-reports:
			m.sup.onReport(r, time.Now())
		case t := <-ticker.C:
			m.sup.onTick(t)
		}
	}
}

// runAuditDrain 在普通优先级把 ring 里的固定事件码翻成审计记录并落库。轮询驱动，
// 避免让 RT 生产者为唤醒它而触碰 channel 锁。
func (m *Module) runAuditDrain() {
	defer close(m.drainDone)
	ticker := time.NewTicker(drainInterval)
	defer ticker.Stop()
	for {
		m.drainAll()
		select {
		case <-m.drainStop:
			// drainStop 在两条 Lane 都退出（或超时放弃）之后才关，因此此刻 ring 里
			// 是 Lane 写入的【全部】事件，最后一次排空不会漏掉停机末尾的投递
			m.drainAll()
			m.reportDropped()
			return
		case <-ticker.C:
		}
	}
}

func (m *Module) drainAll() {
	for {
		rec, ok := m.ring.pop()
		if !ok {
			return
		}
		m.recordEvent(rec)
	}
}

func (m *Module) recordEvent(rec eventRecord) {
	ev := audit.Event{
		Action:  "safety." + rec.kind.String(),
		Subject: "kernel",
		Detail:  fmt.Sprintf("epoch=%d reason=%s phase=%s", rec.epoch, rec.reason, rec.phase),
	}
	switch rec.kind {
	case evDeliveryFault, evProviderAcceptTimeout, evDeviceAckTimeout, evStandstillTimeout:
		ev.Denied = true // 标记「未达期望的安全事件」，便于离线筛
	}
	m.aud.Record(context.Background(), ev)
}

func (m *Module) reportDropped() {
	if n := m.ring.droppedCount(); n > 0 {
		m.aud.Record(context.Background(), audit.Event{
			Action:  "safety.audit_dropped",
			Subject: "kernel",
			Denied:  true,
			Detail:  fmt.Sprintf("dropped=%d", n),
		})
	}
}

// SafetySnapshot 实现 Observer：一致读取顶层状态、epoch 与当前停止相位。
//
// 相位只在它与当前 Gate epoch 属于同一轮锁存时才报告；否则它是上一轮的残留，报告
// StopPhaseUnspecified（本轮 Supervisor 尚未开始跟踪）。这样观察面看到的 (epoch, phase)
// 永远自洽。
func (m *Module) SafetySnapshot() Snapshot {
	st, ep := m.gate.Snapshot()
	ph, phEpoch := unpackPhase(m.phase.Load())
	if phEpoch != ep {
		ph = PhaseUnspecified
	}
	return Snapshot{State: st, Epoch: ep, StopPhase: ph}
}

// RequestRecovery 请求进入 OEM 恢复阶段（SAFETY_LATCHED → OEM_RECOVERY）。恢复动作
// 只能经专用 Safety Gate 请求白名单动作，不能清除 latch；真实白名单派发留到 Provider 落地。
// 返回是否成功迁移。
func (m *Module) RequestRecovery() bool {
	ok := m.gate.BeginRecovery()
	wake(m.superWake)
	return ok
}

// RequireRearm 要求必须经明确 re-arm 才能回 NORMAL（→ REARM_REQUIRED）。
func (m *Module) RequireRearm() bool {
	ok := m.gate.RequireRearm()
	wake(m.superWake)
	return ok
}

// Rearm 执行明确 re-arm（REARM_REQUIRED → NORMAL 并递增 epoch）。返回是否成功。
//
// 内核在这里只复核【不可绕过的硬前置】：停止进度必须已经落定——要么正常链已到
// OUTPUT_DISABLED/STANDSTILL_CONFIRMED（输出确认关闭），要么已入 DELIVERY_FAULT/
// STANDSTILL_TIMEOUT 这类终态旁支（已经必须人工处置）。停止还在途中
// （REQUESTED/SENT/PROVIDER_ACCEPTED/MCU_ACKED）就解开 latch，等于在还不知道输出有没有
// 关掉的情况下重新放行运动。
//
// 「此刻该不该 re-arm」本身是【策略】，不在内核：由系统服务聚合设备状态、风险与用户
// 策略后决定，再来调本方法。机制在内核、策略在服务——与 §8.2 休息模式同一分工
// （Agent 只能请求，Policy 检查后由 nervud Authority 执行固定类型化动作）。
func (m *Module) Rearm() bool {
	_, ep := m.gate.Snapshot()
	ph, phEpoch := unpackPhase(m.phase.Load())

	// 相位必须【属于当前这一轮锁存】（phEpoch == 当前 Gate epoch）且已落定。属于上一轮
	// 的残留相位一律当作「未落定」拒绝——否则会出现：上一轮 OUTPUT_DISABLED → Rearm →
	// 新 Trip → RequireRearm → Rearm 时，最后这次 Rearm 拿旧相位当凭据，把【新】latch
	// 解回 NORMAL，而本轮 beginHalt/RevokeAll 可能都还没跑。绑定 epoch 正是为了堵死它。
	if phEpoch != ep || !rearmSettled(ph) {
		m.recordRearmRejected(ph, phEpoch, ep)
		return false
	}

	if !m.gate.Rearm() {
		// 硬前置通过，但状态迁移仍失败：当前非 REARM_REQUIRED 态，或并发 Trip 改写了
		// 状态。决策基线「被拒的 re-arm 必须留审计」对这条路径同样成立
		m.recordRearmRejected(ph, phEpoch, ep)
		return false
	}
	wake(m.superWake)
	return true
}

// recordRearmRejected 记一条被拒的 re-arm。带上相位与两个 epoch，便于离线区分
// 「相位未落定」「相位属于旧一轮」「状态迁移失败」三种拒因。
func (m *Module) recordRearmRejected(ph StopPhase, phEpoch, gateEpoch uint64) {
	m.aud.Record(context.Background(), audit.Event{
		Action:  "safety.rearm_rejected",
		Subject: "kernel",
		Denied:  true,
		Detail:  fmt.Sprintf("phase=%s phase_epoch=%d gate_epoch=%d", ph, phEpoch, gateEpoch),
	})
}

// rearmSettled 报告停止进度是否已经落定到允许 re-arm 的相位（见 Rearm 的说明）
//
// 注意 rank() 对终态旁支与 UNSPECIFIED 都返回 0，因此终态必须单独判断，
// 不能只比大小
func rearmSettled(p StopPhase) bool {
	return p.rank() >= PhaseOutputDisabled.rank() || p.isTerminalFault()
}
