// 本文件实现内建 endpoint: 由 nervud 自己实现, 不经外部 Service 的 Interface.
//
// # 为什么需要它
//
// 有些能力天生长在内核里, 不可能由 Provider 提供: Safety re-arm (解开停机锁存),
// 整机健康档位, 控制主体快照. 它们要么直接操作内核状态, 要么就是内核状态本身.
//
// 但 App 与系统服务要用到它们, 而控制面上唯一的调用形态是
// ResolveEndpoint -> Request -> Response. 于是只有两条路: 给 Envelope 加新 body,
// 或者让 nervud 自己拥有 endpoint.
//
// envelope.proto 把第一条堵死了: "想加一个新 body 之前先问: 它是否属于上面那
// 八件事之一; 不是就应该做成某个 Interface 的 method. "re-arm 不属于建立连接,
// 发现 endpoint, 发起调用, 返回结果, 取消, 订阅, 推送事件, 维持连接中的任何一件.
//
// 所以走第二条: nervud 注册内建 endpoint, 调用方用完全标准的 Resolve+Request
// 访问, 不知道也不需要知道对面是内核还是 Provider.
//
// # 它与外部注册的三处差别
//
//  1. 不经 RegisterEndpoint wire, 因此不需要 manifest exports 声明, 也不查
//     perm.service.register - 内核不是 Package, 那两道校验对它没有意义.
//  2. 没有 conn. 外部 registration 的 conn 用于 Dispatch 转发与断线失效;
//     内建的执行发生在进程内, 没有可断的连接, 因此恒 live.
//  3. Route 返回一个 Handler 而不是 TargetConn, ipc 据此走本地执行分支.
//
// # 权限仍然照常裁决
//
// 内建不等于免检. Resolve 与 Route 使用中央 catalog 的接口级和 method 级
// 权限. "谁实现的"与"谁能调"是两件独立的事.
package endpoint

import (
	"context"
	"fmt"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// BuiltinCall carries the same trusted call context that an external dispatch
// route has. Conn is deliberately included for route-bound transfer control.
type BuiltinCall struct {
	Context  context.Context
	Conn     ConnHandle
	Caller   identity.Caller
	MethodID uint32
	Payload  []byte
}

type BuiltinResult struct {
	// Payload 是成功时的响应载荷, 类型由 MethodMeta.response_type 决定.
	Payload []byte

	// ErrorDetail 是失败时的 typed 细因, 类型由 MethodMeta.error_detail_type
	// 决定. 空表示只有 Code, 没有更细的原因.
	//
	// # 为什么不复用 Payload
	//
	// 复用的话, "这段字节该按 response_type 还是 error_detail_type 解"就取决于
	// Code - 而那是一个要靠读实现才知道的约定. 分成两个字段之后, 填错的是
	// 类型不匹配, 编译期或校验期就会暴露.
	//
	// # 内建为什么可以带 detail, 而外部 Provider 不行
	//
	// Provider 的 error_detail 当前被内核整条拒绝 (见 method_gate.go):
	// StatusCode 与 domain reason 之间没有机器可读的授权关系, 一份来自外部
	// 进程的 detail 看起来"已认证"却语义无据.
	//
	// 内建不同 - detail 由内核代码生成, 与 Code 出自同一处判定. 这不是给
	// 内建开后门, 是那条顾虑在这里根本不成立.
	ErrorDetail []byte

	Code ipcv1.StatusCode
}

// BuiltinHandler executes one in-kernel endpoint method. The handler returns a
// wire status explicitly; unclassified Go errors must not leak into protocol
// behavior.
type BuiltinHandler func(BuiltinCall) BuiltinResult

// BuiltinSubscribeCall 是一次订阅准入询问.
//
// 只在事件声明了 EventMeta.scoped 时发生. 没声明的事件是 endpoint 作用域
// 的, 谁能 Resolve 到这个 endpoint 谁就能订, 不需要再问.
type BuiltinSubscribeCall struct {
	Caller  identity.Caller
	EventID uint32
	// Scope 是 Subscribe.scope 原值, 即调用方想观察的那个实例.
	//
	// 内核已经看懂了它: scope 是 Envelope 上的一个 uint64, 不需要按
	// Provider 的 schema 解码. 实现只需回答"这个调用方能不能看它".
	Scope uint64
}

// BuiltinSubscribeResult 是准入结果. Code 为 OK 表示放行, 其余值原样回给订阅方.
type BuiltinSubscribeResult struct {
	Code ipcv1.StatusCode
}

// BuiltinSubscribeAdmitter 判定一次订阅是否放行.
//
// # 为什么这道判定必须在 Subscribe 时做, 而不是扇出时过滤
//
// 订上了再逐条丢弃会让调用方以为自己在观察, 然后一直等一个永远不来的事件.
// "订不上"是一次明确的失败, 调用方立刻知道该怎么办.
//
// # 内建与外部 Provider 走不同的判定, 但同一套 wire
//
// 内建的所有权归内核自己 (operation 就是 nervud 的), 一次查表就能回答,
// 所以直接用本回调. 外部 Provider 的所有权只有它自己知道, 靠 BindEventScope(54)
// 预先登记给 internal/ipc 的归属表 - 两条路径在 Subscribe 上是同一个 body,
// 同一个 scope 字段, 客户端分辨不出差别, 也不需要分辨.
//
// 本函数跑在连接的读循环里, 因此实现不得阻塞, 不得 panic.
// 它是内核代码, 两条都由作者保证.
type BuiltinSubscribeAdmitter func(BuiltinSubscribeCall) BuiltinSubscribeResult

// RegisterBuiltin 注册一个由 nervud 自己实现的 Interface.
//
// 装配期调用 (main.go), 不在运行期动态增删 - 内建能力是内核的一部分,
// 随二进制固定. 重复注册同一个 interfaceID 会返回错误而不是覆盖: 静默覆盖
// 会让"哪个实现在生效"取决于装配顺序, 是最难排查的那类问题.
func (m *Module) RegisterBuiltin(interfaceID string, major, minor uint32, h BuiltinHandler) error {
	if m == nil {
		return fmt.Errorf("endpoint: nil module")
	}
	if interfaceID == "" || h == nil {
		return fmt.Errorf("endpoint: builtin %q requires a non-empty id and handler", interfaceID)
	}
	snapshot := m.snapshot()
	if snapshot == nil {
		return fmt.Errorf("endpoint: builtin %q has no authoritative catalog snapshot", interfaceID)
	}
	provider, ok := snapshot.ProviderInterface(
		catalog.KernelPackageID, interfaceID, major)
	if !ok || provider.PackageID != catalog.KernelPackageID ||
		provider.ComponentID == "" ||
		provider.Definition.InterfaceID != interfaceID ||
		provider.Definition.Major != major ||
		provider.ProviderOwner.Kind != catalog.SourceKindKernel {
		return fmt.Errorf("endpoint: builtin %q@%d is not owned by the kernel catalog",
			interfaceID, major)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, reg := range m.byInterface[interfaceID] {
		if reg.builtin != nil && reg.ifaceMajor == major {
			return fmt.Errorf("endpoint: builtin %q@%d already registered", interfaceID, major)
		}
	}

	m.builtinSeq++
	reg := &serviceRegistration{
		id:                   m.builtinSeq,
		packageID:            catalog.KernelPackageID,
		componentID:          provider.ComponentID,
		interfaceID:          interfaceID,
		ifaceMajor:           major,
		ifaceMinor:           minor,
		schemaHash:           append([]byte(nil), provider.Definition.SchemaHash...),
		definitionGeneration: provider.Definition.DefinitionGeneration,
		providerGeneration:   provider.DefinitionGeneration,
		// 内建 endpoint 跨 Package 可见: 它是平台能力, 不属于任何一个包.
		// 能不能调由权限决定, 不由可见性决定.
		visibility: visibilityPublicForBuiltin,
		generation: 1,
		// 恒 live: 没有会断的连接. 外部 registration 靠 conn 断开置 false,
		// 内建的执行发生在进程内, 只要 nervud 活着它就可用.
		live:    true,
		builtin: h,
	}
	m.byInterface[interfaceID] = append(m.byInterface[interfaceID], reg)
	return nil
}

// BuiltinEndpointID 返回一个内建接口的 registration 句柄.
//
// 事件扇出需要它: 扇出键是 (ProviderConn, EndpointID, EventID, Scope), 而内建
// 没有 conn, EndpointID 就是唯一能定位事件源的东西.
//
// 必须与 RouteEvent 给订阅方的那个是同一个数字. 订阅登记用 RouteEvent 的
// ProviderEndpointID, 扇出用这里的返回值; 对不上就是订阅方永远收不到事件 -
// 而两边都不报错, 因为各自看来都是合法的键.
func (m *Module) BuiltinEndpointID(interfaceID string, major uint32) (uint64, bool) {
	if m == nil {
		return 0, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, reg := range m.byInterface[interfaceID] {
		if reg.builtin != nil && reg.ifaceMajor == major {
			return reg.id, true
		}
	}
	return 0, false
}

// RegisterBuiltinSubscriber 给一个已注册的内建接口装上订阅准入.
//
// 必须在 RegisterBuiltin 之后调用. 分成两步而不是给 RegisterBuiltin 加参数:
// 四个内建里只有一个需要准入, 让另外三个都写一个 nil 会让"不需要"和
// "忘了写"在代码里长得一模一样.
func (m *Module) RegisterBuiltinSubscriber(
	interfaceID string, major uint32, admit BuiltinSubscribeAdmitter,
) error {
	if m == nil {
		return fmt.Errorf("endpoint: nil module")
	}
	if admit == nil {
		return fmt.Errorf("endpoint: builtin %q@%d requires a non-nil admitter",
			interfaceID, major)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, reg := range m.byInterface[interfaceID] {
		if reg.builtin == nil || reg.ifaceMajor != major {
			continue
		}
		if reg.subscribeAdmit != nil {
			// 重复注册会让"哪一个准入在生效"取决于装配顺序. 与 RegisterBuiltin
			// 拒绝重复注册同一条理由.
			return fmt.Errorf("endpoint: builtin %q@%d already has a subscribe admitter",
				interfaceID, major)
		}
		reg.subscribeAdmit = admit
		return nil
	}
	return fmt.Errorf("endpoint: builtin %q@%d is not registered", interfaceID, major)
}

// visibilityPublicForBuiltin 是内建 endpoint 的可见性.
//
// 用一个具名常量而不是直接写 pkgregistry.VisibilityPublic, 是为了让
// "内建为什么是 public"这件事有地方解释: 内建能力属于平台, 不属于任何一个
// Package, 因此不存在"只对同包可见"的语义. 能不能调由权限决定.
const visibilityPublicForBuiltin = pkgregistry.VisibilityPublic
