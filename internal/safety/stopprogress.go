package safety

// StopPhase 是与顶层 Safety Gate 正交的「实际停止进度」相位（架构 §6 / NRCP §14.1）。
//
// SAFETY_LATCHED 在触发点即刻原子生效；本相位只跟踪物理停止到底走到哪一步。没有
// 编码器/速度估计等可信停稳证据的设备只能封顶到 OUTPUT_DISABLED，不得把「PWM/输出
// 已归零」伪装成 STANDSTILL_CONFIRMED。
//
// 数值必须与 nervus-ipc safety.proto 的 StopPhase 枚举一致（proto 是唯一真源）。
type StopPhase uint8

const (
	PhaseUnspecified StopPhase = 0

	// 正常推进链（单调前进）。
	PhaseRequested        StopPhase = 1
	PhaseSent             StopPhase = 2
	PhaseProviderAccepted StopPhase = 3
	PhaseMCUAcked         StopPhase = 4
	PhaseOutputDisabled   StopPhase = 5

	// 有可信证据时才可到达。
	PhaseStandstillConfirmed StopPhase = 6

	// 终态旁支：任意非终态可进入，不可逆。
	PhaseDeliveryFault     StopPhase = 7
	PhaseStandstillTimeout StopPhase = 8
)

func (p StopPhase) String() string {
	switch p {
	case PhaseRequested:
		return "REQUESTED"
	case PhaseSent:
		return "SENT"
	case PhaseProviderAccepted:
		return "PROVIDER_ACCEPTED"
	case PhaseMCUAcked:
		return "MCU_ACKED"
	case PhaseOutputDisabled:
		return "OUTPUT_DISABLED"
	case PhaseStandstillConfirmed:
		return "STANDSTILL_CONFIRMED"
	case PhaseDeliveryFault:
		return "DELIVERY_FAULT"
	case PhaseStandstillTimeout:
		return "STANDSTILL_TIMEOUT"
	default:
		return "UNSPECIFIED"
	}
}

// rank 给正常推进相位一个单调序号；旁支终态与 Unspecified 返回 0（单独处理）。
func (p StopPhase) rank() int {
	switch p {
	case PhaseRequested:
		return 1
	case PhaseSent:
		return 2
	case PhaseProviderAccepted:
		return 3
	case PhaseMCUAcked:
		return 4
	case PhaseOutputDisabled:
		return 5
	case PhaseStandstillConfirmed:
		return 6
	default:
		return 0
	}
}

func (p StopPhase) isTerminalFault() bool {
	return p == PhaseDeliveryFault || p == PhaseStandstillTimeout
}

// stopTracker 跟踪单个执行器 Resource（[REWRITE-v1] 只有 base.main）的停止进度。
// 只在 Supervisor goroutine 内访问，无需同步。
type stopTracker struct {
	phase               StopPhase
	standstillSupported bool // 来自 Safety Contract：无证据能力时封顶 OUTPUT_DISABLED
	terminal            bool
}

// begin 重置跟踪器到 REQUESTED，并记录本设备是否具备可信停稳证据能力。
func (t *stopTracker) begin(standstillSupported bool) {
	t.phase = PhaseRequested
	t.standstillSupported = standstillSupported
	t.terminal = false
}

// advance 尝试把相位推进到 to，返回是否发生了有效推进。规则：
//
//   - 已入终态：不再变化。
//   - 终态旁支（DELIVERY_FAULT / STANDSTILL_TIMEOUT）：可从任意非终态进入，不可逆。
//   - STANDSTILL_CONFIRMED：需要 standstillSupported；否则封顶在 OUTPUT_DISABLED
//     （不接受伪停稳，NRCP §14.1）。
//   - 其余正常相位：只能单调前进（rank 严格增大）。
func (t *stopTracker) advance(to StopPhase) bool {
	if t.terminal {
		return false
	}
	if to.isTerminalFault() {
		t.phase = to
		t.terminal = true
		return true
	}
	if to == PhaseStandstillConfirmed && !t.standstillSupported {
		// 无停稳证据能力：最多推进到 OUTPUT_DISABLED。
		if t.phase.rank() < PhaseOutputDisabled.rank() {
			t.phase = PhaseOutputDisabled
			return true
		}
		return false
	}
	if to.rank() > t.phase.rank() {
		t.phase = to
		return true
	}
	return false
}
