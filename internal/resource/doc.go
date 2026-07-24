// Package resource 是 Resource Registry：持有"当前机器人 Profile 里有哪些
// Resource、它们的规范 resource_type/role/resource_handle/access_mode"这份权威
// 定义，并把 (resource_type, role) 解析成运行期 resource_handle（设计方案
// Resource模块设计方案.md §1）
//
// [REWRITE-v1] v1 内容是编译期常量，不查任何 manifest；只有单一执行器
// Resource base.main，供 internal/control 退化为单一 Lease 槽
// exclusive_control 使用。ControlLease 的执行/裁决、Provider 动态绑定、
// 运行期 state 追踪、对外 ListResources/RobotCatalog RPC，均明确不在本包
// 职责内（设计方案 §1），留待 v2+
package resource
