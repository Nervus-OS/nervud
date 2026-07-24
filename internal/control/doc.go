// Package control 管理 HUMAN/AI ControlLease 与 deadman，并在 lease 生命周期事件上
// 读或递增 internal/motiongate.Gate 持有的共享 motion epoch。safety 与 control
// 必须共用同一个 Gate，否则锁存状态与撤销世代号可能分叉。
//
// # 控制权模型
//
// ControlLease 从语义第一天起就是 Resource-scoped；v1 唯一合法 Scope 为
// {base.main}，因此内部退化为单个租约槽的 exclusive_control。
//
//	SAFETY > HUMAN > AI > NONE
//
// 这只是有效控制来源的产品层排序，且其含义仅限于执行器与运动控制权，不代表
// 全系统权限等级，也不代表 CPU 调度优先级。四者不共用同一种
// owner 枚举或 Lease 实现：
//
//	SAFETY 独立 Gate/latch（internal/safety），不是普通 lease
//	HUMAN  普通 lease，Class = ClassHuman
//	AI   普通 lease，Class = ClassAI
//	NONE  nil lease - 客户端不能申请它，它是当前没有有效租约的结论
//
// 并发不靠优先级维度解决，靠 Resource 维度：人遥控底盘时 AI 仍可控制其它 Resource。
// v1 只有 base.main 一个执行器 Resource，所以这一层暂时看不出来，但 API
// 形状从第一天就是 Resource-scoped，v2 放开时调用方不用改。
//
// # Class 由调用方裁决，本包不信任何自报值
//
// 远程客户端在请求里写 source=HUMAN 一律不可信。真正的裁决必须在 IPC
// 请求管线通过身份、Permission 和 Policy 完成，control 只在拿到已裁决的 Class 之后
// 执行租约状态机。同理，AI 现在该不该自主行动由 Agent Service 的策略决定，本包
// 不查任何 policy - 内核层不设这道闸门是一个已知取舍（见下）。
//
// # 依赖方向
//
// 只依赖 motiongate / audit / identity / scheduler，不 import safety：safety 侧的
// LeaseRevoker 是消费者定义的窄接口，*control.Module 隐式满足，装配因此单向无环
// （main.go 先构造 control，再把它注入 safety.New）。
//
// 因 import scheduler（其 sched.go 带 //go:build linux）本包整体是 linux-only，
// 与 internal/safety 一致。
//
// # 并发模型（三条硬规则）
//
//	cur  atomic.Pointer[Lease] 读侧完全无锁：Check/Refresh 每条运动命令走一次，零堆分配
//	mu   sync.Mutex       只序列化 control 自己的变更路径（签发/续租/释放/撤销/到期）
//	fresh atomic.Int64      deadman 新鲜度，记距单调基准的纳秒，避免每条命令重建 Lease
//
// 1. RevokeAll 绝不取 mu。它由 safety 的 Supervisor Lane（FIFO 90）在 beginHalt 里调用；
// Go 的 mutex 没有优先级继承，等一个普通优先级的持锁者就是 FIFO 90 上的优先级反转。
// 它只做一次 atomic Swap，并把被撤的租约交给 Control Lane 事后记账。
//
// 2. RevokeAll 不递增 epoch。每个边界只能递增一次，而 safety 触发时
// gate.Trip 已经递增过了；这里再递增就是 churn。
//
// 3. 签发采用发布后复核：递增 epoch -> 发布租约 -> 重读 Gate；若此刻已锁存或 epoch
// 再次变化，说明这条租约诞生即失效，立刻撤下。配合 Check 每次比对
// lease.Epoch == gate.Epoch，构成三重 fail-closed - 即使签发与 Safety 触发并发，
// 也不可能存在一条能授权运动的租约。
//
// # Control Lane
//
// 模块自持一条 Lane（SCHED_RR / scheduler.PrioControl = 40），负责 deadline 与 deadman
// 的到期检测。它低于 PREEMPT_RT threaded IRQ 的 50，按 internal/scheduler 的规则允许
// 等 I/O，因此可以直接在 Lane 上落审计（audit 底层是非阻塞 AsyncWriter）。
//
// 注意这与 Safety Stop Lane（FIFO 95）的零堆分配硬规则不同，不要互相套用：那条
// 规则针对的是急停投递路径，本 Lane 不在急停路径上。真正要求零分配的是 Check/Refresh
// - 它们在每条运动命令上被调用，由 AllocsPerRun 测试守住。
//
// # v1 已知取舍
//
//   - 内核层没有机器人能不能自主动的闸门：AI lease 的签发只受 Permission、Safety
//     与 Resource 状态约束，自主模式策略在 Agent Service。
//   - 没有 on-behalf-of 归因：App 经 Agent 触发的动作，租约持有者是 Agent Service。
//     内核审计只保证租约生命周期（签发/撤销的时刻与 epoch）可与 Agent Service 自己的
//     日志对齐；Agent 崩溃丢日志时追溯链会断。
package control
