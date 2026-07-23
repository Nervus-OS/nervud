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
	phase         atomic.Uint32 // 当前 StopPhase，供 SafetySnapshot 读取
	wake          chan struct{} // 唤醒 Stop Lane（cap 1）
	superWake     chan struct{} // 唤醒 Supervisor（cap 1）

	ring *auditRing  // MPSC：Stop Lane + Supervisor 生产，auditDrain 消费
	sup  *supervisor // 只在 Supervisor goroutine 内访问

	// 生命周期。
	stopCh    chan struct{}
	stopOnce  sync.Once
	fatal     chan error // cap 1，FatalReporter
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
		drainDone: make(chan struct{}),
	}
	m.phase.Store(uint32(PhaseUnspecified))
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
	if err := m.spawner.SpawnDedicated("safety-stop",
		scheduler.PolicyFIFO, scheduler.PrioSafetyLatch,
		m.laneFn("safety-stop", m.runStopLane)); err != nil {
		return fmt.Errorf("safety: start stop lane: %w", err)
	}
	if err := m.spawner.SpawnDedicated("safety-supervisor",
		scheduler.PolicyFIFO, scheduler.PrioSafety,
		m.laneFn("safety-supervisor", m.runSupervisor)); err != nil {
		return fmt.Errorf("safety: start supervisor lane: %w", err)
	}
	go m.runAuditDrain()
	if m.log != nil {
		m.log.Info("safety: armed", "stop_prio", scheduler.PrioSafetyLatch, "supervisor_prio", scheduler.PrioSafety)
	}
	return nil
}

// Stop 关闭 stopCh 让两条 Lane 与 auditDrain 干净退出，并等审计收尾落盘。
// RT Lane 的 goroutine 由 Scheduler 的 wg 统一 join（sched.Shutdown 在所有模块 Stop 之后）。
func (m *Module) Stop(_ context.Context) error {
	m.stopOnce.Do(func() { close(m.stopCh) })
	select {
	case <-m.drainDone:
	case <-time.After(stopDrainTimeout):
	}
	return nil
}

// Fatal 实现 kernel.FatalReporter：任一 Lane 在 stopCh 未关时退出（异常或关闭序被打乱）
// 即上报致命错误，触发内核反序关停、非零退出、systemd 重启（MCU 心跳兜底）。
func (m *Module) Fatal() <-chan error { return m.fatal }

// laneFn 包裹 Lane 主体，把「未经 Stop 就退出」识别为结构性故障并上报 Fatal。
func (m *Module) laneFn(name string, body func(context.Context)) func(context.Context) {
	return func(ctx context.Context) {
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
		case <-m.stopCh:
			m.drainAll() // 收尾再排空一次
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
func (m *Module) SafetySnapshot() Snapshot {
	st, ep := m.gate.Snapshot()
	return Snapshot{State: st, Epoch: ep, StopPhase: StopPhase(m.phase.Load())}
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
func (m *Module) Rearm() bool {
	ok := m.gate.Rearm()
	wake(m.superWake)
	return ok
}
