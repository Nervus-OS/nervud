// Package control 管理 HUMAN/AI ControlLease 与 deadman, 并在 lease 生命周期事件上
// 读或递增 internal/motiongate.Gate 持有的共享 motion epoch. safety 与 control
// 必须共用同一个 Gate, 否则锁存状态与撤销世代号可能分叉.
//
// # 控制权模型
//
// ControlLease 是 Resource-scoped: 每个已经由 catalog 解析并验证的非空稳定 handle
// 各有一个 exclusive_control 槽. control 不认识 base/arm/未来执行器的类型名.
//
//	SAFETY > HUMAN > AI > NONE
//
// 这只是有效控制来源的产品层排序, 且其含义仅限于执行器与运动控制权, 不代表
// 全系统权限等级, 也不代表 CPU 调度优先级. 四者不共用同一种
// owner 枚举或 Lease 实现:
//
//	SAFETY 独立 Gate/latch (internal/safety), 不是普通 lease
//	HUMAN 普通 lease, Class = ClassHuman
//	AI 普通 lease, Class = ClassAI
//	NONE nil lease - 客户端不能申请它, 它是当前没有有效租约的结论
//
// 并发不靠优先级维度解决, 靠 Resource 维度: 人遥控底盘时 AI 仍可控制其它 Resource.
// 同一连接可以同时持有多个 Resource; 抢占, 续租与 deadman 都只作用于目标槽.
//
// # Class 策略边界
//
// control 不推断调用者是 HUMAN 还是 AI, 只消费上层传入的 Class. 当前 IPC 明确允许
// 调用方自选并审计, 因此 HUMAN 不是额外身份特权; 未来若收紧, 策略仍应在 IPC/权限层
// 完成, 本包的 Resource 槽与抢占状态机无需修改.
//
// # 依赖方向
//
// 只依赖 motiongate / audit / identity / scheduler, 不 import safety: safety 侧的
// LeaseRevoker 是消费者定义的窄接口, *control.Module 隐式满足, 装配因此单向无环
//
//	(main.go 先构造 control, 再把它注入 safety.New).
//
// 数据面通过 SetLeaseObserver 注入同样窄的 LeaseObserver, 不让 control import
// transfer. 任何已生效 Lease 的终止边界只通知一次; Safety 的 RevokeAll 只写每槽预分配
// 的待处理位置, 由普通优先级的 drainRevoked 延后通知, 绝不在 Safety Supervisor Lane
// 回调外部代码.
//
// 因 import scheduler (其 sched.go 带 //go:build linux) 本包整体是 linux-only,
// 与 internal/safety 一致.
//
// # 并发模型 (三条硬规则)
//
//	slots atomic.Pointer[slotIndex] 不可变槽目录, 读侧无锁, 扩容时 copy-on-write
//	cur/fresh 每个 Resource 各一组原子槽, Check/Refresh 零堆分配且互不续命
//	mu sync.Mutex 只序列化 control 自己的普通变更路径 (签发/续租/释放/撤销/到期)
//
// 1. RevokeAll 绝不取 mu. 它由 safety 的 Supervisor Lane (FIFO 90) 在 beginHalt 里调用;
// Go 的 mutex 没有优先级继承, 等一个普通优先级的持锁者就是 FIFO 90 上的优先级反转.
// 它只扫描一次不可变槽快照, 对每个 cur 做 atomic Swap, 并把被撤租约留在对应槽内,
// 交给 Control Lane 事后记账.
//
// 2. RevokeAll 不递增 epoch. 每个边界只能递增一次, 而 safety 触发时
// gate.Trip 已经递增过了; 这里再递增就是 churn.
//
// 3. motion epoch 是全局单调 token 分配器, 但普通租约边界只撤目标 Resource; 其它槽保留
// 自己的 token. Safety Trip 的 epoch 记录为全局 floor, floor 及之前的所有租约都失效.
// 签发仍采用发布后复核 (Gate + RevokeAll seqlock), 并发 Safety 不可能穿透.
//
// # Control Lane
//
// 模块自持一条 Lane (SCHED_RR / scheduler.PrioControl = 40), 负责 deadline 与 deadman
// 的到期检测. 它低于 PREEMPT_RT threaded IRQ 的 50, 按 internal/scheduler 的规则允许
// 等 I/O, 因此可以直接在 Lane 上落审计 (audit 底层是非阻塞 AsyncWriter).
//
// 注意这与 Safety Stop Lane (FIFO 95) 的零堆分配硬规则不同, 不要互相套用: 那条
// 规则针对的是急停投递路径, 本 Lane 不在急停路径上. 真正要求零分配的是 Check/Refresh
// - 它们在每条运动命令上被调用, 由 AllocsPerRun 测试守住.
//
// # v1 已知取舍
//
//   - 内核层没有机器人能不能自主动的闸门. 当前 AcquireControl 本身只受 Safety,
//     Resource 与租约状态机约束; Permission 在具体 method 的派发门上重新裁决.
//     因此无 method 权限的调用方发不了命令, 但仍可能占住一个 lease 槽. 把 class/会话
//     资格或申请租约权限收紧, 属于未来 IPC/权限策略点, 不应下沉到 Provider.
//   - 没有 on-behalf-of 归因: App 经 Agent 触发的动作, 租约持有者是 Agent Service.
//     内核审计只保证租约生命周期 (签发/撤销的时刻与 epoch) 可与 Agent Service 自己的
//     日志对齐; Agent 崩溃丢日志时追溯链会断.
package control
