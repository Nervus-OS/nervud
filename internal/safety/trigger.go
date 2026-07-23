package safety

// Trip 是 Safety 触发入口（零堆分配、lock-free）。可从任意 goroutine 调用：未来的
// IPC Safety 方法 handler、Controller.RequestStop（HUMAN/UI 急停）、Supervisor 升级、
// OEM Safety Gate、以及测试。
//
// 三步：
//  1. gate.Trip()：原子锁存 SAFETY_LATCHED 并递增 motion epoch。锁存在本调用返回时
//     即刻生效，不依赖任何 Lane 调度（架构 §14.1）——已排队/在途命令随即按新 epoch 作废。
//  2. 记录最新触发原因（可 coalesce：并发多次触发都汇成同一次锁存）。
//  3. 非阻塞唤醒 Stop Lane（做 RT 优先级投递）与 Supervisor（开始跟踪与计时）。
//
// 即便 Stop Lane/Supervisor 因故未醒，锁存也已生效、adapter 会按 epoch 拒绝，MCU 心跳
// 仍是 Level-0 兜底。
func (m *Module) Trip(reason ReasonCode) {
	m.gate.Trip()
	m.pendingReason.Store(uint32(reason))
	wake(m.wake)
	wake(m.superWake)
}

// RequestStop 实现 Controller：受权限的软件急停等价于一次 Trip。
func (m *Module) RequestStop(reason ReasonCode) { m.Trip(reason) }

// wake 非阻塞地在容量 1 的信号 channel 上投一个唤醒。channel 已满（已有待处理唤醒）
// 时走 default——多次唤醒被自然合并成一次。零堆分配。
func wake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
