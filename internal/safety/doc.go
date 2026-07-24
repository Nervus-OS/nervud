// Package safety 是 NSOS 三层安全信任边界中的第 1 层：不可绕过的内核停机决定。
//
// # 三层信任边界（信任级别递减、彼此独立）
//
//  1. 内核 nervud（软实时，永远在，不可绕过）
//     原子锁存 SAFETY_LATCHED，递增 motion epoch 撤销在途或排队命令，并撤销 lease
//     状态机 / 超时升级 / re-arm；Stop Lane(FIFO 95) + Supervisor(FIFO 90) 都在进程内
//  2. OEM Provider（系统服务，可替换，尽力而为）
//     这台机器具体怎么停：抱闸/卸力/趴下/切电/关火 - 只有 OEM 知道
//     manifest 声明 safety_contract；收 SafetyHalt -> 执行 -> 回 HaltAccepted/StopProgress/...
//     其高优先级由 nervud 授予、从属于内核 Stop Lane，永不是仲裁者；OEM 代码绝不进本 TCB
//  3. MCU/ESP32（硬实时，独立，Level-0 兜底）
//     心跳看门狗在 Host 或链路失效时本地停机，并拒绝旧 session、sequence 和 epoch
//
// 安全的决定权和撤销权留在第 1 层；设备动作由第 2 层尽力执行；第 3 层负责最终兜底。
// 服务快、慢或退出都不影响第 1 层已经完成的 latch 与撤权；Linux 退出后由第 3 层独立刹停。
//
// # 顶层状态机
//
//	NORMAL -> SAFETY_LATCHED -> OEM_RECOVERY(可选) -> REARM_REQUIRED -> NORMAL
//
// SAFETY_LATCHED 在触发点即刻原子生效，不等 Provider/串口/MCU ACK 或机械停稳。实际停止
// 进度用正交的 StopProgress 相位跟踪（REQUESTED -> ... -> OUTPUT_DISABLED -> [STANDSTILL_CONFIRMED]，
// 旁支 DELIVERY_FAULT/STANDSTILL_TIMEOUT）；无可信停稳证据的设备只能封顶到 OUTPUT_DISABLED。
//
// # 两条 RT Lane
//
//	Stop Lane    FIFO 95（scheduler.PrioSafetyLatch）：最短的投递路径
//	Safety Supervisor FIFO 90（scheduler.PrioSafety）：状态机、超时预算、升级、re-arm 观察
//
// 96..99 段保留给内核实时线程，避免用户态 Lane 饿死内核关键线程。
//
// # Stop Lane 零堆分配硬规则（ ；CI 门禁）
//
// 触发热路径（Trip -> 唤醒 -> deliverHalt）预热后必须零堆分配：channel、固定命令、
// 审计 ring、SafetyPath 缓冲全部启动时预分配；禁止 new、会扩容的 append、闭包任务、
// 日志格式化、Protobuf 编码、普通 RPC/writer 队列、慢锁进入。审计由普通优先级的
// auditDrain 读取固定事件码后完成。trigger_alloc_test.go 和 bench_test.go
// 持续验证该路径为零堆分配，避免急停受 GC 或分配器锁影响。
//
// motion epoch 与 latch 的原子核心在叶子包 internal/motiongate，safety 与 control 共用。
package safety
