// Package endpoint 负责 Endpoint 注册、解析（Resolve）、connection binding 与路由
// endpoint_id 是不透明、连接作用域的路由句柄，由 nervud 生成，SDK 只缓存使用
//
// 职责边界：
//   - Register：Service 通过 RegisterEndpoint 报到一个它已实现的 Interface
//   - Resolve：Caller 把 interface_id 解析成本连接作用域的 endpoint_id，解析时
//     完成一次权限裁决（接口级，见 catalog.go）
//   - Binding 生命周期：维护 (connection, endpoint_id) -> 目标 的映射，连接断线/
//     主动 Unregister 时使 binding 失效
//   - 路由查表：为 ipc 的 Request 分派回答"这个 endpoint_id 现在应该转发给
//     哪条 Service 连接的哪个 service 侧 endpoint_id"
//
// 不负责：route_id 分配/Dispatch 关联/执行 Lane 调度（留在 ipc）、Resource
// Registry（留给 internal/resource，v1 只硬编码校验 base.main）、方法级
// Method Registry（留待 schema 工具链落地）、[v2+] caller-filtered 目录投影。
//
// v1 是纯被动失效形态：EndpointDied/EndpointRevoked 的主动推送依赖 ipc 连接
// 写路径的独立 writer goroutine，本包尚不依赖它 -
// 每次 Route 都重新做一次存活与权限复核，足以保证"撤权/断线后下一次调用必然
// 失败"，只是不如主动推送及时。
package endpoint
