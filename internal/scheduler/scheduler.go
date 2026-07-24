// 本文件定义 Policy、优先级常量与 Lane 类型。实际调度调用只在 Linux 构建中存在，
// 因为非 Linux 的静默降级会制造已经获得实时优先级的假象

package scheduler

// Policy 映射 Linux 的 SCHED_FIFO、SCHED_RR 和 SCHED_OTHER
type Policy int

const (
	// PolicyNormal 普通分时调度（Linux SCHED_OTHER）。System/Background 用
	PolicyNormal Policy = iota
	// PolicyFIFO 实时先进先出（Linux SCHED_FIFO）：同优先级不轮转，跑到主动让出为止
	// 用于 Emergency Stop 与 Safety Supervisor 这类一旦要跑就必须立刻跑完的路径
	PolicyFIFO
	// PolicyRR 实时时间片轮转（Linux SCHED_RR）：同优先级按时间片轮流
	// 用于 Control Lane 这类需要实时性、但允许同级公平轮转的路径
	PolicyRR
)

func (p Policy) String() string {
	switch p {
	case PolicyFIFO:
		return "SCHED_FIFO"
	case PolicyRR:
		return "SCHED_RR"
	default:
		return "SCHED_OTHER"
	}
}

// 实时优先级取值（Linux SCHED_FIFO/RR 合法范围 1..99，99 最高）
// 这些数字表示调度先后，不表示 CPU 占用百分比，也不存在优先级 100
//
// 为什么上限取 95 而不是 99：
//
//	真机上内核自己的实时线程（migration/N、watchdog/N）跑在 FIFO 99
//	SCHED_FIFO 同优先级不轮转 - 谁先上 CPU 就跑到主动让出为止 - 所以用户态
//	占住 99 可能把 migration 堵在后面，后果是内核级的（stop-machine 卡死）
//	lockup detector 失效）。96..99 整段留给内核，用户态不得使用
//
// 与 threaded IRQ 的相对位置（PREEMPT_RT 上 irq/N-* 默认 FIFO 50）：
//
//	高于 50 的 lane 不得同步等待任何 I/O 完成，否则会饿死给自己送数据的中断
//	线程（优先级反转）。Stop Lane 因此只投递启动时预构造的固定停止信号
//	写完即走、不等确认。低于 50 的 lane 才可以正常等 I/O
//
// 无论优先级高低，lane 一律不得自旋：优先级决定谁先跑，是否阻塞决定
// 跑多久，后者才是饿死别人的直接原因。内核默认 RT throttling 为每 1s
// 周期最多 950ms（/proc/sys/kernel/sched_rt_runtime_us），跑飞的 lane 会被
// 强制停 50ms - 对急停路径而言这是不可接受的延迟
//
// 编号之间留有间隙，插入新 lane 时不必重排既有数值（重排优先级极易漏改一处）
const (
	// 96..99 保留给内核实时线程，用户态不得使用

	PrioSafetyLatch    = 95 // Emergency Stop Lane：最短的锁存/撤权/刹停路径
	PrioSafety         = 90 // Safety Supervisor：状态机、超时与恢复许可
	PrioSafetySupervLo = 85 // 预留：Supervisor 慢路径（尚无消费者）
	PrioWatchdogFeed   = 80 // 预留：MCU 心跳喂狗（被饿死会导致误刹停）
	PrioMotionTick     = 75 // 预留：周期性运动/状态更新

	// 74..51 预留：需要抢占 threaded IRQ 的新 lane 加在这一段
	// 50 = PREEMPT_RT threaded IRQ 默认优先级，跨过这条线语义改变（见上）

	PrioControl   = 40 // Control Lane：HUMAN/AI 控制指令下发
	PrioTelemetry = 30 // 预留：实时性要求较低的采集/上报

	// 29..1 预留：其余实时性要求更低的 lane
	// 优先级 0 = SCHED_OTHER，ipc / audit / pkgregistry / service 等控制面模块用
)

// setSched 在已 LockOSThread 的当前线程上应用调度策略。实现位于带 Linux build tag
// 的 sched.go；不提供非 Linux no-op，避免 Safety Lane 在无实时保证时继续运行

// Lane 是一条绑定到专属 OS 线程、并被赋予固定调度策略的执行通道
// 目前只是骨架：字段与装配方式待 Safety/Control 落地时补全
//
// TODO(rewrite): 加入预分配的定长命令 channel、固定停止信号、writer FD 等。
// Stop Lane 热路径必须零堆分配，并由 benchmark 校验，避免 GC 延迟急停
type Lane struct {
	name     string
	policy   Policy
	priority int
}

// applySelf 在当前 goroutine 已经 LockOSThread的前提下，把本 Lane 的调度策略
// 施加到当前 OS 线程。调用方必须先 runtime.LockOSThread 且不得 Unlock
// 否则设置会落到一个随后可能被复用的线程上，语义错误
func (l *Lane) applySelf() error {
	return setSched(l.policy, l.priority)
}
