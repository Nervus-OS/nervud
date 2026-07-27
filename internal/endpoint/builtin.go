// 本文件实现【内建 endpoint】：由 nervud 自己实现、不经外部 Service 的 Interface。
//
// # 为什么需要它
//
// 有些能力天生长在内核里，不可能由 Provider 提供：Safety re-arm（解开停机锁存）、
// 整机健康档位、控制主体快照。它们要么直接操作内核状态，要么就是内核状态本身。
//
// 但 App 与系统服务要用到它们，而控制面上唯一的调用形态是
// ResolveEndpoint → Request → Response。于是只有两条路：给 Envelope 加新 body，
// 或者让 nervud 自己拥有 endpoint。
//
// envelope.proto 把第一条堵死了：「想加一个新 body 之前先问：它是否属于上面那
// 八件事之一；不是就应该做成某个 Interface 的 method。」re-arm 不属于建立连接、
// 发现 endpoint、发起调用、返回结果、取消、订阅、推送事件、维持连接中的任何一件。
//
// 所以走第二条：nervud 注册内建 endpoint，调用方用【完全标准】的 Resolve+Request
// 访问，不知道也不需要知道对面是内核还是 Provider。
//
// # 它与外部注册的三处差别
//
//  1. 不经 RegisterEndpoint wire，因此不需要 manifest exports 声明，也不查
//     perm.service.register —— 内核不是 Package，那两道校验对它没有意义。
//  2. 没有 conn。外部 registration 的 conn 用于 Dispatch 转发与断线失效；
//     内建的执行发生在进程内，没有可断的连接，因此恒 live。
//  3. Route 返回一个 Handler 而不是 TargetConn，ipc 据此走本地执行分支。
//
// # 权限仍然照常裁决
//
// 内建不等于免检。Resolve 与 Route 使用中央 catalog 的接口级和 method 级
// 权限。「谁实现的」与「谁能调」是两件独立的事。
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
	Payload []byte
	Code    ipcv1.StatusCode
}

// BuiltinHandler executes one in-kernel endpoint method. The handler returns a
// wire status explicitly; unclassified Go errors must not leak into protocol
// behavior.
type BuiltinHandler func(BuiltinCall) BuiltinResult

// RegisterBuiltin 注册一个由 nervud 自己实现的 Interface。
//
// 装配期调用（main.go），不在运行期动态增删——内建能力是内核的一部分，
// 随二进制固定。重复注册同一个 interfaceID 会返回错误而不是覆盖：静默覆盖
// 会让「哪个实现在生效」取决于装配顺序，是最难排查的那类问题。
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
		// 内建 endpoint 跨 Package 可见：它是平台能力，不属于任何一个包。
		// 能不能调由权限决定，不由可见性决定。
		visibility: visibilityPublicForBuiltin,
		generation: 1,
		// 恒 live：没有会断的连接。外部 registration 靠 conn 断开置 false，
		// 内建的执行发生在进程内，只要 nervud 活着它就可用。
		live:    true,
		builtin: h,
	}
	m.byInterface[interfaceID] = append(m.byInterface[interfaceID], reg)
	return nil
}

// visibilityPublicForBuiltin 是内建 endpoint 的可见性。
//
// 用一个具名常量而不是直接写 pkgregistry.VisibilityPublic，是为了让
// 「内建为什么是 public」这件事有地方解释：内建能力属于平台，不属于任何一个
// Package，因此不存在「只对同包可见」的语义。能不能调由权限决定。
const visibilityPublicForBuiltin = pkgregistry.VisibilityPublic
