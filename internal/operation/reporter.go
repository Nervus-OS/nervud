// 本文件是 Provider 回报接缝：Provider 经 nervud（dispatch/provider 回路）回报
// 进度与终态，nervud 校验转移合法性及 origin/epoch 绑定后落库。Provider
// 不拥有最终系统 Operation 状态，也不能在系统取消后继续
// 控制资源 - 本文件的转移校验与终态只写一次（CAS）就是这条铁律的执法点。
package operation

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
)

// ProviderReporter 是 operation 定义、供 dispatch/provider 回路持有的窄接口
// （*Manager 隐式满足）。全部方法都要求 nervud 校验后才落库：Provider 只报告
// 事实，系统裁决状态。
type ProviderReporter interface {
	// Accept Provider 接受并开始执行 -> RUNNING。epoch 必须与创建时绑定的
	// MotionEpoch 一致，否则该 operation 诞生的撤销世代已过期，fail-closed。
	Accept(id, epoch uint64) error
	// Progress typed 进度事件，不改变 state（仅 RUNNING/CANCEL_REQUESTED 期间）。
	Progress(id uint64, payload []byte) error
	// Succeed 真实成功 -> SUCCEEDED（terminal_status=OK，可选 typed result）。
	Succeed(id uint64, result []byte) error
	// Fail 失败/设备故障 -> FAILED（terminal_status=非OK非CANCELLED，可选 detail）。
	Fail(id uint64, code ipcv1.StatusCode, detail []byte) error
	// Cancelled Provider 确认已取消并停止控制资源 -> CANCELLED。
	Cancelled(id uint64) error
}

// 编译期断言：*Manager 满足 ProviderReporter。
var _ ProviderReporter = (*Manager)(nil)

// Accept 把 operation 从 PENDING 推进到 RUNNING。
//
// epoch 校验：Provider 报告它开始执行时所处的 motion epoch。若与创建时绑定的
// MotionEpoch 不符，说明世界已越过一个撤销边界（Safety 触发 / lease 变更），
// 这条 operation 不该再进入 RUNNING - 直接失败并返回 ErrStaleEpoch，执法
// "系统取消后不得继续控制资源"。
func (m *Manager) Accept(id, epoch uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return ErrNotFound
	}
	if op.State.Terminal() {
		return ErrAlreadyTerminal
	}
	if epoch != op.MotionEpoch {
		// 陈旧 epoch：失败收敛，不进入 RUNNING。
		m.terminateLocked(op, StateFailed, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION, nil,
			actionFailed, ErrStaleEpoch)
		return ErrStaleEpoch
	}
	// 抢占检查：即便 epoch 与创建时一致，世界仍可能已越过一条更晚的撤销边界，或本
	// operation 已过 deadline。这两种情况下绝不进入 RUNNING - 就地收敛为 FAILED。
	if code, pcause, ok := m.supersededOrExpiredLocked(op); ok {
		m.terminateLocked(op, StateFailed, code, nil, actionFor(code), pcause)
		return pcause
	}
	if !canTransition(op.State, StateRunning) {
		m.record(actionIllegal, op, true, ErrIllegalTransition)
		return ErrIllegalTransition
	}
	m.transitionLocked(op, StateRunning)
	m.record(actionAccepted, op, false, nil)
	return nil
}

// Progress 投递一条 typed 进度事件，不改变 state。只在 RUNNING/CANCEL_REQUESTED
// 期间合法（PENDING 尚未开始、终态已结束都无进度可言）。
func (m *Manager) Progress(id uint64, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return ErrNotFound
	}
	if op.State != StateRunning && op.State != StateCancelRequested {
		return ErrNotRunning
	}
	m.emitLocked(op, Event{
		OperationID: op.ID,
		Kind:        EventProgress,
		State:       op.State,
		Origin:      op.Origin,
		Payload:     cloneBytes(payload),
	})
	return nil
}

// Succeed 真实成功终结 -> SUCCEEDED。允许从 RUNNING 或 CANCEL_REQUESTED 抢先
// 终结，因为设备可能在取消送达前已经完成。
func (m *Manager) Succeed(id uint64, result []byte) error {
	return m.reportTerminal(id, StateSucceeded, ipcv1.StatusCode_STATUS_CODE_OK, result, actionSucceeded, nil)
}

// Fail 失败/设备故障终结 -> FAILED。code 必须是 Provider 可合法产生的失败原因；
// 任何越权或非法的 code 一律 fail-closed 归一化为 INTERNAL（，绝不静默
// 当成成功或取消，也不让 Provider 冒充只能由 nervud 产生的裁决）。归一化发生时
// reportTerminal 会把它审计为 Provider Contract 违规。
func (m *Manager) Fail(id uint64, code ipcv1.StatusCode, detail []byte) error {
	norm := code
	var contractViolation error
	if !providerFailCode(norm) {
		norm = ipcv1.StatusCode_STATUS_CODE_INTERNAL
		contractViolation = ErrProviderContract
	}
	return m.reportTerminal(id, StateFailed, norm, detail, actionFailed, contractViolation)
}

// providerFailCode 报告 code 是否是 Provider 可以合法在 Fail 里产生的失败原因。
// 白名单式 fail-closed：只放行明确属于"设备/执行侧失败"的通用状态。
//   - OK/CANCELLED/UNSPECIFIED：不是失败原因（分别是成功、取消裁决、零值哨兵）。
//   - PERMISSION_DENIED/UNAUTHENTICATED：授权裁决只能由 nervud 产生，Provider
//     冒充即契约违规。
//   - ACCEPTED：是投递回执，不是终态原因。
//   - 未知/未来枚举：一律不放行（白名单外即拒）。
func providerFailCode(code ipcv1.StatusCode) bool {
	switch code {
	case ipcv1.StatusCode_STATUS_CODE_INTERNAL,
		ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
		ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
		ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED,
		ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
		ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
		ipcv1.StatusCode_STATUS_CODE_NOT_FOUND:
		return true
	default:
		return false
	}
}

// Cancelled Provider 确认已取消并停止控制资源 -> CANCELLED。仅 CANCEL_REQUESTED
// 可确认取消（canTransition 保证：RUNNING 直接 Cancelled 是非法转移，会被拒并记审计）。
func (m *Manager) Cancelled(id uint64) error {
	return m.reportTerminal(id, StateCancelled, ipcv1.StatusCode_STATUS_CODE_CANCELLED, nil, actionCancelled, nil)
}

// reportTerminal 是三个终态回报的公共实现，落实"终态只写一次"：
//
//   - 已是同一终态：幂等 no-op，返回 nil。
//   - 已是不同终态：终态不可覆盖，记审计并返回 ErrAlreadyTerminal
//     （并发的 Succeed/Fail/Cancelled 由 mu 决出唯一胜者，败者走这里）。
//   - 越过撤销边界/已过 deadline：晚到的 Provider 推进绝不允许成功，同步
//     收敛为 FAILED 并返回原因（见下方"抢占检查"，）。
//   - 转移非法（如 RUNNING -> CANCELLED）：记审计并返回 ErrIllegalTransition。
//   - 否则：CAS 写入终态（terminateLocked），返回 nil。
//
// 抢占检查是本函数的关键防线：SafetySupersede/deadline 收敛都在后台异步做，
// 在"边界已越过"与"后台扫描到它"之间存在一个窗口。若不在这里同步复检，一个晚到
// 的 Succeed 会在这个窗口里把 operation 写成 SUCCEEDED，后台随后因已是终态而跳过
// - 等于让 Safety/lease 撤销/deadline 被一次晚到的成功回报击穿。因此这里在持锁、
// 尚未终结时就地判定：凡应被接管/超时的 operation，一律就地收敛为 FAILED，绝不放
// 它成功。这样无论后台是否已扫到，同步路径都先一步 fail-closed。
func (m *Manager) reportTerminal(id uint64, to State, status ipcv1.StatusCode, detail []byte, action string, cause error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return ErrNotFound
	}
	if op.State == to {
		return nil // 幂等：同终态重复回报当 no-op
	}
	if op.State.Terminal() {
		m.record(actionIllegal, op, true, ErrAlreadyTerminal)
		return ErrAlreadyTerminal
	}
	// 抢占检查（在放行任何 Provider 终态之前）：运动世界可能已在这条 operation
	// 之下越过一条撤销边界，或它已过 deadline。这两种情况下，Provider 无论报成功
	// 还是失败，系统结论都必须是 FAILED - 就地收敛，不让晚到者改写裁决。
	if code, pcause, ok := m.supersededOrExpiredLocked(op); ok {
		m.terminateLocked(op, StateFailed, code, nil, actionFor(code), pcause)
		return pcause
	}
	if !canTransition(op.State, to) {
		m.record(actionIllegal, op, true, ErrIllegalTransition)
		return ErrIllegalTransition
	}
	m.terminateLocked(op, to, status, detail, action, terminalCauseFor(to, cause))
	return nil
}

// supersededOrExpiredLocked 判定 op 此刻是否应被系统接管（返回收敛用的 code +
// 原因 + true）。顺序：先 Safety 撤销边界（最强），再 deadline。要求持有 mu。
func (m *Manager) supersededOrExpiredLocked(op *Operation) (ipcv1.StatusCode, error, bool) {
	// 运动类且诞生于当前撤销边界之前 -> 被 Safety/lease 撤销接管。
	if op.LeaseID != 0 {
		if boundary := m.supersedeEpoch.Load(); boundary != 0 && op.MotionEpoch < boundary {
			return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION, ErrSuperseded, true
		}
	}
	// deadline 已过。
	if !op.Deadline.IsZero() && m.now().After(op.Deadline) {
		return ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED, ErrDeadlineExceeded, true
	}
	return ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED, nil, false
}

// actionFor 把抢占收敛的 code 映射到对应审计 Action，与后台收敛路径同名。
func actionFor(code ipcv1.StatusCode) string {
	if code == ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED {
		return actionDeadlineExceeded
	}
	return actionSafetySuperseded
}

// terminalCauseFor 让审计的 Denied/Err 只对非正常终结（FAILED）置位；正常的
// SUCCEEDED/CANCELLED 不算被拒。cause 非 nil（如 Provider 契约违规）优先透传，
// 否则 FAILED 落通用 provider-failure 原因。
func terminalCauseFor(to State, cause error) error {
	if cause != nil {
		return cause
	}
	if to == StateFailed {
		return errProviderFailed
	}
	return nil
}

var errProviderFailed = errStr("provider reported failure")
