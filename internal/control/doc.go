// Package control 管理 HUMAN/AI ControlLease 与 deadman，并在 lease 生命周期事件上
// 读/递增 internal/motiongate.Gate 持有的【共享】motion epoch（该 Gate 由 safety 与
// control 共用同一实例；epoch 不归任一方独占，见 internal/motiongate 包文档）。
// ControlLease 从语义第一天起就是 Resource-scoped；[REWRITE-v1] 唯一合法 Scope 为 {base.main
// SAFETY > HUMAN > AI > NONE 只是有效控制来源排序，四者不共用同一种 owner 枚举或 Lease 实现
package control
