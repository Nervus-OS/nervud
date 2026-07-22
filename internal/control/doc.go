// Package control 管理 HUMAN/AI ControlLease、deadman 与 motion epoch
// ControlLease 从语义第一天起就是 Resource-scoped；[REWRITE-v1] 唯一合法 Scope 为 {base.main
// SAFETY > HUMAN > AI > NONE 只是有效控制来源排序，四者不共用同一种 owner 枚举或 Lease 实现
package control
