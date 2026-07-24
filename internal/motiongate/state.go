package motiongate

// State 是顶层 Safety 状态机的状态：
//
//	NORMAL -> SAFETY_LATCHED -> OEM_RECOVERY(可选) -> REARM_REQUIRED -> NORMAL
//
// 取值从 1 起，0 保留为 StateInvalid，使零值 Gate 不落在任何可放行态；
// epoch==0 同样无效，因此未初始化状态会双重 fail-closed。
type State uint8

const (
	// StateInvalid 是零值哨兵：未经 New 的 Gate 会解出它。永远不是合法运行态，
	// 也永远不允许下发运动。
	StateInvalid State = 0

	// StateNormal 普通运行：在 epoch 与 lease 也满足时，允许下发运动命令。
	StateNormal State = 1

	// StateSafetyLatched Safety 已锁存：普通运动 Gate 关闭，已排队/在途命令按新
	// epoch 整体作废。触发点即刻原子生效，不等 Provider/MCU ACK 或机械停稳。
	StateSafetyLatched State = 2

	// StateOEMRecovery 可选的 OEM 恢复阶段：仍处于安全语义之下，不是 Normal；
	// 恢复动作只能经专用 Safety Gate 请求白名单动作，不能清除 latch。
	StateOEMRecovery State = 3

	// StateRearmRequired 恢复结束或被要求复位，等待明确 re-arm 才能回 Normal。
	StateRearmRequired State = 4
)

// String 返回稳定的顶层状态名，供日志、审计和外部状态投影共用。
func (s State) String() string {
	switch s {
	case StateNormal:
		return "NORMAL"
	case StateSafetyLatched:
		return "SAFETY_LATCHED"
	case StateOEMRecovery:
		return "OEM_RECOVERY"
	case StateRearmRequired:
		return "REARM_REQUIRED"
	default:
		return "INVALID"
	}
}
