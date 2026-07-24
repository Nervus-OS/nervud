// Package motiongate 是 Safety/运动的共享原子核心：一个打包的 atomic.Uint64
// 同时表达顶层 Safety 状态与 motion epoch（执行器命令的撤销世代号）。
//
// # 打包布局
//
// 单个 64 位字，一次原子读即得到一致的 (state, epoch)：
//
//	bit 63 .......... 56 | bit 55 ................. 0
//	  8 位 State    |    56 位 epoch
//
// 为什么打包成一个字：Safety 触发要求原子锁存状态和递增 epoch 一步到位。
// 分成两个独立 atomic 既无法一次读到一致快照，也无法
// 一步完成latch 且 bump。打包后 Trip 是一次 CAS、Snapshot 是一次 Load。
//
// # 依赖方向
//
// 本包是叶子，禁止 import 任何 nervud 兄弟模块。safety 与 control 共用同一个
// *Gate 实例（由 main.go 装配时 New 一次并注入两者） - 它属于可信计算基（TCB）。
// 因此不能有归属之争：谁都不拥有epoch，它是二者共享的撤销世代号。
//
// # 生命周期与 fail-closed
//
// 必须经 New 创建。New 置 State=Normal、epoch=1：
//   - epoch 恒非零（初始化非零 epoch）。epoch==0 永远是无效世代，
//     执行器/adapter 复核到 epoch==0 一律拒绝下发。
//   - 零值 Gate（word==0）解出 (StateInvalid, 0)：状态既非 Normal、epoch 又无效，
//     双重 fail-closed - 未初始化或被清零的 Gate 不会被误判为可以运动。
//
// # 并发
//
// 全部方法 lock-free 且零堆分配（Trip/BumpEpoch/Snapshot 由 AllocsPerRun 分配测试
// 守住）。热路径（Safety 触发）只调用 Trip，是一次不阻塞、不分配的 CAS。
package motiongate
