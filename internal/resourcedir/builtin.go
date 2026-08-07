// 本包把「这台机器上有哪些资源」包成一个【内建 endpoint】，供 nervud 在装配期
// 注册（endpoint.RegisterBuiltin）。只读。
//
// # 它补的是一个真实的缺口
//
// ResourceSelector 能回答「把我接到那个前视摄像头上」，却回答不了「这台机器上
// 到底有几个摄像头」。缺了后者，App 只能靠反复 Resolve 去试探——试到 NOT_FOUND
// 为止。那既慢又不可靠：一次失败的 Resolve 分不清「没有这个设备」和
// 「有但我没权限」。
//
// # 为什么由内核实现而不是某个系统服务
//
// 资源目录【就是 Catalog 本身】。让一个服务来代答，等于让它维护一份 Catalog
// 的副本，而副本与真身之间必然存在一个可以漂移的窗口：装包已经生效、副本还
// 没刷新，App 拿到的就是一份过期的设备清单。本包直接读 catalog.Registry 的
// 当前 Snapshot，不存在这个窗口。
//
// 这与「内核不该为某个能力开后门」并不冲突：目录不是某个能力，它是 Catalog
// 的读接口。本包不认识摄像头，也不认识底盘。
//
// # 边界：只返回一次成功 Resolve 已经会暴露的信息
//
// handle / 类型 / role / 访问模式 / 风险级 / 标签。【不含】设备节点路径、
// 序列号、Provider PID。这条边界是硬的——目录是所有持有 perm.resource.query
// 的 App 都能读的东西，往里加一个「顺便也返回一下」的字段，就等于把那个字段
// 公开给了全系统。
package resourcedir

import (
	"log/slog"

	resourcedirv1 "github.com/nervus-os/nervus-ipc/protocol/interface/resourcedirv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
)

// BuiltinInterfaceID 是本内建接口的 ID。
//
// 必须与 catalog bootstrap 里的那次 bootstrapInterface 调用一致——那里定门槛。
const BuiltinInterfaceID = catalog.InterfaceResourceDirectory

// MethodListResources 取自生成代码的枚举值。
//
// 【不在本地重抄一个字面量 1】：抄一份的代价不是重复，是它会悄悄过期——
// proto 改了号，这里还是旧值，症状是调用被路由到一个不存在的方法。
// 与 safety 同一做法（power 因为还没有 .proto 才不得不手写，见那边的说明）。
const MethodListResources = uint32(
	resourcedirv1.ResourceDirectoryMethod_RESOURCE_DIRECTORY_METHOD_LIST_RESOURCES)

// Module 持有目录查询所需的最小依赖。
type Module struct {
	definitions *catalog.Registry
	log         *slog.Logger
}

// New 构造 Module。definitions 为 nil 时 handler 一律 fail-closed 回 UNAVAILABLE。
func New(definitions *catalog.Registry, log *slog.Logger) *Module {
	return &Module{definitions: definitions, log: log}
}

// BuiltinHandler 返回可直接交给 endpoint.RegisterBuiltin 的处理函数。
func (m *Module) BuiltinHandler() endpoint.BuiltinHandler {
	return func(call endpoint.BuiltinCall) endpoint.BuiltinResult {
		switch call.MethodID {
		case MethodListResources:
			return m.listResources(call.Payload)
		default:
			// fail closed：没实现的方法就是不存在。回一个空列表会让调用方
			// 以为这台机器上什么资源都没有。
			return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
		}
	}
}

func (m *Module) listResources(payload []byte) endpoint.BuiltinResult {
	if m == nil || m.definitions == nil {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE}
	}

	req := &resourcedirv1.ListResourcesRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		// 解不开的请求是调用方的错，不是内核的。回 INVALID_ARGUMENT 而不是
		// 当成空请求列出全部——那会把一次编码错误变成一次全量泄漏。
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT}
	}

	// 一次读定，整份响应来自【同一个 Snapshot】。分两次读会让响应里混进
	// 两个 Catalog 修订版的内容，出现「列出了一个刚被卸载的资源」这类
	// 无法复现的结果。
	matched := catalog.FilterResources(
		m.definitions.Current(), req.GetResourceType(), req.GetStableRole(), req.GetLabels())

	out := &resourcedirv1.ResourceList{
		Resources: make([]*resourcedirv1.ResourceEntry, 0, len(matched)),
	}
	for _, def := range matched {
		out.Resources = append(out.Resources, entryOf(def))
	}

	wire, err := proto.Marshal(out)
	if err != nil {
		if m.log != nil {
			m.log.Warn("resourcedir: marshal response failed", "err", err)
		}
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL}
	}
	return endpoint.BuiltinResult{Payload: wire, Code: ipcv1.StatusCode_STATUS_CODE_OK}
}

// entryOf 把 Catalog 的资源定义投影成 wire 上的公开条目。
//
// 【逐字段显式列出，不做整体拷贝】：ResourceDefinition 将来长出内部字段
// （Provider PID、设备节点）时，显式列举会让新字段默认【不】外泄，而
// 反射拷贝会让它默认外泄。默认方向决定了忘记时会发生什么。
func entryOf(def catalog.ResourceDefinition) *resourcedirv1.ResourceEntry {
	entry := &resourcedirv1.ResourceEntry{
		Handle:       def.Handle,
		ResourceType: def.ResourceType,
		StableRole:   def.StableRole,
		AccessMode:   def.AccessMode,
		RiskClass:    def.RiskClass,
	}
	if len(def.Labels) > 0 {
		entry.Labels = make(map[string]string, len(def.Labels))
		for key, value := range def.Labels {
			entry.Labels[key] = value
		}
	}
	return entry
}
