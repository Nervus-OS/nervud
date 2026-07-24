// 本文件是本包的核心数据模型（设计方案 §4）：两个独立的 endpoint_id 命名空间
// （service 侧 registration / caller 侧 binding）必须分开生成、分开存储——
// 同一个数字在两条连接上毫无关系（架构 §10.5）
package endpoint

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// ConnHandle 是某条 IPC 连接的不透明身份，由 internal/ipc 的 *conn 满足
//
// 本包不知道也不需要知道 conn 的具体形状（避免反向依赖 ipc，见 doc.go 的
// 依赖方向说明），只需要它能作为可比较的 map key 唯一标识一条连接——
// "另一个连接上的相同数字不是同一个 binding"靠的正是这份指针身份，
// 而不是数字本身（架构 §10.5）
type ConnHandle interface{}

// RouteInfo 是 Route 查表成功后交给 ipc 的转发目标
//
// route_id 分配、Dispatch/DispatchResult 关联、执行 Lane 调度不在本包范围内
// （设计方案 §1），ipc 拿到 RouteInfo 后自行处理
type RouteInfo struct {
	TargetConn        ConnHandle
	ServiceEndpointID uint64
	ResourceHandle    string
}

// RouteError 是 Route 查表失败的结果
//
// Code 为零值（StatusCode_STATUS_CODE_UNSPECIFIED）表示未失败，调用方据此
// 判空，照抄 ipcv1.Failure 系列对 zero code 的既有处理约定
type RouteError struct {
	Code ipcv1.StatusCode
}

// componentKey 唯一标识一个组件实例，供 on-demand 拉起等待队列使用
// （照抄 internal/service 的同名 key 形状）
type componentKey struct {
	pkg  string
	comp string
}

// registrationKey 唯一标识一个 (Package, Component, Interface) 三元组，
// 用于生成递增的 generation 号（供 binding 复核陈旧性，见 serviceRegistration）
type registrationKey struct {
	pkg   string
	comp  string
	iface string
}

// serviceRegistration 是一个 Service 通过 RegisterEndpoint 报到的一个
// Interface 实现（设计方案 §4）
type serviceRegistration struct {
	id             uint64 // service 侧命名空间，RegisterEndpointSuccess.endpoint_id
	conn           ConnHandle
	packageID      string
	componentID    string
	interfaceID    string
	ifaceMajor     uint32
	ifaceMinor     uint32
	schemaHash     []byte
	resourceHandle string // v1 固定 "base.main" 或空
	visibility     pkgregistry.Visibility
	generation     uint64 // 每次同一 (pkg,comp,interface) 重新注册递增

	// live 为 false 表示该 registration 已失效（连接断开 / UnregisterEndpoint）。
	// 引用它的 binding 在下次 Route 时据此判定失效——这是 v1 被动失效的落点，
	// 主动 EndpointDied 推送依赖 ipc 写路径升级（设计方案 §3 的 Phase 0），
	// 本包尚不依赖它
	live bool
}

// binding 是一次 ResolveEndpoint 在某条 caller 连接上创建的路由句柄
type binding struct {
	id                 uint64 // caller 侧命名空间，ResolveEndpointSuccess.endpoint_id
	conn               ConnHandle
	callerPackageID    string
	target             *serviceRegistration
	targetGeneration   uint64 // 创建时快照的 serviceRegistration.generation，供诊断
	interfaceMajor     uint32
	interfaceMinor     uint32
	requiredPermission string // 来自 interfaceCatalog，空表示无额外裁决
	resourceHandle     string
}

// connState 是单条连接名下的全部注册与 binding
//
// service 侧 endpoint_id（nextRegID）与 caller 侧 endpoint_id（nextEndpointID）
// 是两个独立命名空间——同一条连接理论上可以既注册又解析（架构 §10.5）
type connState struct {
	nextEndpointID uint64
	nextRegID      uint64
	bindings       map[uint64]*binding
	registrations  map[uint64]*serviceRegistration
}

func newConnState() *connState {
	return &connState{
		bindings:      make(map[uint64]*binding),
		registrations: make(map[uint64]*serviceRegistration),
	}
}
