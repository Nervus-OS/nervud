package safety

// SafetyPath 是内核 Stop Lane 向 OEM Provider 投递高优先级停机请求的边界
// 固定停机信号的接缝。
//
// 实现约束（供真实 eventfd/UDS/硬件 FD 落地时遵守）：
//   - 预分配：连接、缓冲、固定信号在 Provider READY 前就绪，SendHalt 不得再分配。
//   - 非阻塞、零堆分配：写完即返回，不等 ACK；被慢消费者阻塞时立即放弃而不是排队。
//   - 只投递预构造的固定信号；设备特定停止动作由 Provider 的本地高优先级路径负责。
//
// 无论本路径成功与否，MCU motion watchdog、物理急停与独立切断仍是 Level-0 兜底
// （ ）。
type SafetyPath interface {
	SendHalt(epoch uint64, reason ReasonCode) error
}

// NopPath 是 dev / v1 无真实 Provider 时的预分配 no-op 实现：
// 不投递任何东西、零分配、永远成功。真实平台投递用 build-tag 文件另行落地。
func NopPath() SafetyPath { return nopPath{} }

type nopPath struct{}

func (nopPath) SendHalt(uint64, ReasonCode) error { return nil }
