package safety

// ReasonCode 是固定的数字触发原因码。它用于零堆分配的审计 ring：Safety 触发热路径
// 只写这个 uint32，普通优先级的 auditDrain 再把它翻成审计文本。绝不在热路径做字符串
// 格式化或 Protobuf 编码（ ：审计由普通优先级线程读取固定事件码后完成）。
//
// 数值必须与 nervus-ipc safety.proto 的 HaltReason 枚举保持一致（proto 是唯一真源，
// 本地 const 只是镜像）；跨语言一致性由 golden 测试守住。0 恒为未指定并 fail-closed。
type ReasonCode uint32

const (
	ReasonUnspecified          ReasonCode = 0 // 永远不是合法触发原因；未初始化/未知落这里
	ReasonOperatorEStop        ReasonCode = 1 // 人工/UI 软件急停
	ReasonDeadmanTimeout       ReasonCode = 2 // deadman / 命令新鲜度失效
	ReasonProviderFault        ReasonCode = 3 // Provider 上报故障触发
	ReasonHeartbeatLost        ReasonCode = 4 // 与 Provider/MCU 心跳丢失
	ReasonSupervisorEscalation ReasonCode = 5 // Supervisor 超时升级触发
	ReasonExternalTrip         ReasonCode = 6 // 外部（如 MCU/独立硬件）上报导致的锁存
)

func (r ReasonCode) String() string {
	switch r {
	case ReasonOperatorEStop:
		return "OPERATOR_ESTOP"
	case ReasonDeadmanTimeout:
		return "DEADMAN_TIMEOUT"
	case ReasonProviderFault:
		return "PROVIDER_FAULT"
	case ReasonHeartbeatLost:
		return "HEARTBEAT_LOST"
	case ReasonSupervisorEscalation:
		return "SUPERVISOR_ESCALATION"
	case ReasonExternalTrip:
		return "EXTERNAL_TRIP"
	default:
		return "UNSPECIFIED"
	}
}
