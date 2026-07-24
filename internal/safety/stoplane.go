package safety

import "context"

// runStopLane 是 Emergency Stop Lane（FIFO 95）的循环。平时阻塞在 wake 上；被唤醒后
// 投递一次固定停机信号即刻回到阻塞。
//
// 退出：主听模块 stopCh（Stop 关闭它 -> 模块反序停机时干净退出，符合 kernel.Module
// 契约循环退出只听 Stop）；ctx（Scheduler 自己的 ctx）只作兜底 - 它在 sched.Shutdown
// 时才取消，晚于模块 Stop。经 ctx 退出而 stopCh 未关，会被 laneFn 判为异常并上报 Fatal。
func (m *Module) runStopLane(ctx context.Context) {
	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-m.wake:
			m.deliverHalt()
		}
	}
}

// deliverHalt 是 Stop Lane 的热路径：读当前 epoch 与最新原因，向 Provider 的高优先级
// Safety Path 投递固定停机信号，并写一条固定事件码给审计 ring，然后返回。
//
// 零堆分配：Epoch/Load 是原子读，NopPath.SendHalt 不分配，ring.push 不分配。禁止在此
// 做日志格式化 / Protobuf 编码 / 普通 I/O（ ）。
func (m *Module) deliverHalt() {
	epoch := m.gate.Epoch()
	reason := ReasonCode(m.pendingReason.Load())
	if err := m.path.SendHalt(epoch, reason); err != nil {
		m.ring.push(eventRecord{kind: evDeliveryFault, reason: reason, phase: PhaseSent, epoch: epoch})
		return
	}
	m.ring.push(eventRecord{kind: evHaltDelivered, reason: reason, phase: PhaseSent, epoch: epoch})
}
