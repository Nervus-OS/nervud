package safety

import (
	"sync/atomic"
	"time"

	"github.com/nervus-os/nervud/internal/motiongate"
)

// supervisor 是 Safety Supervisor Lane（FIFO 90）的状态：管理 StopProgress 状态机、
// Safety Contract 超时与升级、以及 re-arm 的观察。
//
// 全部字段只在 Supervisor goroutine 内读写（reconcile/onReport/onTick 都在该 goroutine
// 串行执行），因此无需同步——唯一对外发布的只读量是 phase（用 atomic 供 SafetySnapshot）。
type supervisor struct {
	gate     *motiongate.Gate
	ring     *auditRing
	contract Contract
	revoker  LeaseRevoker   // 可为 nil：epoch 递增已是主撤销手段
	phase    *atomic.Uint32 // 发布当前 StopPhase 供外部快照
	pending  *atomic.Uint32 // 读取最新触发原因（由 Trip 写入）

	active    bool      // 当前是否在跟踪一次停机
	haltAt    time.Time // 本次锁存时刻（用于超时预算）
	haltEpoch uint64
	tracker   stopTracker
	esc       escFlags
}

// escFlags 记录各升级动作是否已触发过，保证每次停机每种升级只执行一次。
type escFlags struct {
	acceptTimeout     bool
	deviceAckTimeout  bool
	standstillTimeout bool
}

// reconcile 由 Trip / re-arm / 恢复请求唤醒后调用：把 Supervisor 的跟踪状态与 Gate
// 的权威状态对齐。Gate 是真相，Supervisor 只是围绕它做进度跟踪与升级。
func (s *supervisor) reconcile(now time.Time) {
	st, ep := s.gate.Snapshot()
	switch st {
	case motiongate.StateSafetyLatched:
		// 新锁存，或恢复阶段被新触发重新锁存（epoch 变了）→ 开新一轮跟踪。
		if !s.active || ep != s.haltEpoch {
			s.beginHalt(ep, now)
		}
	case motiongate.StateNormal:
		// 经明确 re-arm 回到 NORMAL：结束跟踪。
		if s.active {
			s.active = false
			s.setPhase(PhaseUnspecified)
			s.push(evRearm, ReasonUnspecified, PhaseUnspecified, ep)
		}
	case motiongate.StateOEMRecovery, motiongate.StateRearmRequired:
		// 仍在安全语义下：保持 active，不改停止跟踪。
	}
}

func (s *supervisor) beginHalt(epoch uint64, now time.Time) {
	s.active = true
	s.haltAt = now
	s.haltEpoch = epoch
	s.esc = escFlags{}
	s.tracker.begin(s.contract.StandstillConfirmationSupported)
	s.setPhase(PhaseRequested)
	s.push(evTripped, ReasonCode(s.pending.Load()), PhaseRequested, epoch)

	// 撤销所有执行器 lease。epoch 递增（已由 gate.Trip 完成）是主撤销手段；revoker
	// 是 control 落地后清理 lease 对象/发 EndpointRevoked 的增量，v1 可为 nil。
	if s.revoker != nil {
		s.revoker.RevokeAll(epoch)
	}
}

// onReport 消费 Provider 的边界上报，推进 StopProgress 状态机。陈旧 epoch 一律忽略。
func (s *supervisor) onReport(r ProviderReport, _ time.Time) {
	if !s.active || r.Epoch != s.haltEpoch {
		return
	}
	switch r.Kind {
	case ReportHaltAccepted:
		if s.tracker.advance(PhaseProviderAccepted) {
			s.setPhase(s.tracker.phase)
			s.push(evStopProgress, ReasonUnspecified, s.tracker.phase, r.Epoch)
		}
	case ReportStopProgress:
		if s.tracker.advance(r.Phase) {
			s.setPhase(s.tracker.phase)
			s.push(evStopProgress, ReasonUnspecified, s.tracker.phase, r.Epoch)
		}
	case ReportStandstillConfirmed:
		if s.tracker.advance(PhaseStandstillConfirmed) {
			s.setPhase(s.tracker.phase)
			// 若设备不支持停稳证据，advance 会封顶到 OUTPUT_DISABLED；据此选事件码。
			kind := evStandstillConfirmed
			if s.tracker.phase != PhaseStandstillConfirmed {
				kind = evStopProgress
			}
			s.push(kind, ReasonUnspecified, s.tracker.phase, r.Epoch)
		}
	case ReportProviderFault:
		if s.tracker.advance(PhaseDeliveryFault) {
			s.setPhase(s.tracker.phase)
			s.push(evDeliveryFault, ReasonProviderFault, s.tracker.phase, r.Epoch)
		}
	}
}

// onTick 周期性检查 Safety Contract 的超时并升级（NRCP §14.4）。任何升级都不清除
// Safety latch、不恢复旧 Lease；只推进跟踪并留审计，实际切电/报警由设备策略与 MCU 承接。
func (s *supervisor) onTick(now time.Time) {
	if !s.active || s.tracker.terminal {
		// 已进入终态（DELIVERY_FAULT / STANDSTILL_TIMEOUT）后不再做超时升级：终态相位
		// rank 为 0，若不挡住会让 accept/deviceAck 的 `rank < X` 判定在故障后又误触发。
		return
	}
	elapsed := now.Sub(s.haltAt)

	// provider_accept_timeout：尚未收到 HaltAccepted。
	if !s.esc.acceptTimeout && s.tracker.phase.rank() < PhaseProviderAccepted.rank() &&
		elapsed > s.contract.ProviderAcceptTimeout {
		s.esc.acceptTimeout = true
		s.push(evProviderAcceptTimeout, ReasonSupervisorEscalation, s.tracker.phase, s.haltEpoch)
		// 标 Provider/Resource FAULT、停普通 Dispatch —— 留待 resource/service 落地接线，v1 仅审计。
	}

	// device_stop_ack_timeout：尚未 OUTPUT_DISABLED。
	if !s.esc.deviceAckTimeout && s.tracker.phase.rank() < PhaseOutputDisabled.rank() &&
		elapsed > s.contract.DeviceStopAckTimeout {
		s.esc.deviceAckTimeout = true
		s.push(evDeviceAckTimeout, ReasonSupervisorEscalation, s.tracker.phase, s.haltEpoch)
	}

	// standstill_timeout：尚未确认停稳（或设备无证据能力）。
	if !s.esc.standstillTimeout && s.tracker.phase.rank() < PhaseStandstillConfirmed.rank() &&
		elapsed > s.contract.StandstillTimeout {
		s.esc.standstillTimeout = true
		s.tracker.advance(PhaseStandstillTimeout) // Latch 保持，进入 timeout 终态
		s.setPhase(s.tracker.phase)
		s.push(evStandstillTimeout, ReasonSupervisorEscalation, s.tracker.phase, s.haltEpoch)
	}
}

func (s *supervisor) setPhase(p StopPhase) { s.phase.Store(uint32(p)) }

func (s *supervisor) push(kind eventKind, reason ReasonCode, phase StopPhase, epoch uint64) {
	s.ring.push(eventRecord{kind: kind, reason: reason, phase: phase, epoch: epoch})
}
