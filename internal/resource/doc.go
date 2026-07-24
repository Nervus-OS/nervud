// Package resource 是 Resource Registry：持有当前机器人 Profile 中 Resource 的
// resource_type、role、resource_handle 和 access_mode 权威定义，并把
// (resource_type, role) 解析成运行期 resource_handle。
//
// v1 v1 内容是编译期常量，不查任何 manifest；只有单一执行器
// Resource base.main，供 internal/control 退化为单一 Lease 槽
// exclusive_control 使用。ControlLease 的执行/裁决、Provider 动态绑定、
// 运行期 state 追踪、对外 ListResources/RobotCatalog RPC 均不在本包职责内，
// 避免静态注册表同时承担执行与动态状态管理
package resource
