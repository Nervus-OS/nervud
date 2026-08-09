// 本包把"哪些包申请了哪些 USER_CONSENT 权限, 用户此刻同不同意"包成一个内建
// endpoint, 供 nervud 在装配期注册 (endpoint.RegisterBuiltin).
//
// # 它补的是一个真实的缺口
//
// USER_CONSENT 权限 (perm.storage.user, perm.camera.capture 这类) 的运行期状态
// 默认是 NotRequested, 而 AllowedAt 对这一档要求状态恰为 Granted 才放行. 也就是
// 说一个申请了这类权限的普通应用, 装上之后【永远】拿不到它 - 除非有人改变那个
// 运行期状态.
//
// 在本接口之前, 全系统能改它的只有 SetRuntimeState, 而它只进得去管理通道
//
//	(nervud-admin.sock, 只放行持 perm.pkg.admin 的包与运维 UID), 实际只有
//
// nervusctl 用得上. 结果是应用装好了, 安装期裁决也过了, 运行期第一次调用就
// PERMISSION_DENIED, 而系统里没有任何界面能解决它, 应用自己也无法申请.
//
// # 为什么由内核实现而不是某个系统服务
//
// 授予状态【就是 permission.Registry 自己的状态】. 让一个服务来代管, 等于把
// "谁能改全系统的危险权限"交给一个可以被替换的包, 而 perm.permission.admin 的
// 门槛 (SYSTEM_ONLY + PLATFORM 信任 + platform-release 签名角色) 正是为了不让它
// 被替换. 与 power / safety.control / resource.directory 同一形态.
//
// # 边界: 只管运行期授予状态, 不管安装期裁决
//
// 安装期集合 (Entry.GrantedPermissions) 由 pkgregistry 的 IntersectAt 算出,
// 回答的是"这个包有没有资格拿这条权限"; 本接口改的是"用户此刻同不同意".
// 两者都通过才等于放行. 因此对一个安装期就没拿到的权限调 SetGrantState 会失败
// —— 界面不该给用户一个按下去等于什么都没发生的开关.
package permissionadmin

import (
	"log/slog"
	"sort"

	permissionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/permissionv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// BuiltinInterfaceID 是本内建接口的 ID.
//
// 必须与 catalog bootstrap 里那次 bootstrapInterface 调用一致 —— 那里定门槛.
const BuiltinInterfaceID = catalog.InterfacePermissionAdmin

// 方法号取自生成代码的枚举值, 不在本地重抄字面量: 抄一份的代价不是重复, 是它
// 会悄悄过期 —— proto 改了号这里还是旧值, 症状是调用被路由到不存在的方法.
// 与 resourcedir / safety 同一做法
const (
	MethodListGrants = uint32(
		permissionv1.PermissionAdminMethod_PERMISSION_ADMIN_METHOD_LIST_GRANTS)
	MethodSetGrantState = uint32(
		permissionv1.PermissionAdminMethod_PERMISSION_ADMIN_METHOD_SET_GRANT_STATE)
)

// PackageLister 是本包对 pkgregistry.Registry 的窄接口依赖: 列出已装包.
// *pkgregistry.Registry 隐式满足
type PackageLister interface {
	List() []pkgregistry.Entry
}

// GrantReader 是本包对 permission.Registry 的窄接口依赖.
//
// 读写分开列出是有意的: 本包做的两件事 (读一份清单, 改一条状态) 风险差着一个
// 数量级, 接口上分开能让"这个方法到底会不会改状态"一眼看出来
type GrantReader interface {
	GrantStateOf(packageID, permissionID string) permission.GrantState
	SetRuntimeState(packageID, permissionID string, state permission.GrantState) error
	// AllowedAt 是"此刻能不能用"的权威结论, 自查接口 (permission.self) 用它.
	//
	// 【必须复用这个方法而不是在本包重算】: 它是内核授权判定的同一处代码,
	// 已经把在不在安装期集合里, 哪一档授予模式, USER_CONSENT 的运行期状态,
	// 以及系统软件的 consent 豁免合起来算过. 重算一份等于造出第二个真相源,
	// 两边一旦不一致, 应用会看到"自查说有, 实际调用被拒".
	//
	// 带 Snapshot 参数是为了让一次回答只用一个 Catalog 修订版 —— 与
	// endpoint.Route 用它的理由相同.
	AllowedAt(definitions *catalog.Snapshot, packageID, permissionID string) bool
}

// Module 持有授权查询与变更所需的最小依赖.
type Module struct {
	definitions *catalog.Registry
	packages    PackageLister
	grants      GrantReader
	log         *slog.Logger
}

// New 构造 Module. 任一依赖为 nil 时 handler 一律 fail-closed 回 UNAVAILABLE:
// 一个读不到定义的授权界面会把"查不到"显示成"没有权限需要授权", 那比报错更糟
func New(
	definitions *catalog.Registry, packages PackageLister, grants GrantReader, log *slog.Logger,
) *Module {
	return &Module{definitions: definitions, packages: packages, grants: grants, log: log}
}

// BuiltinHandler 返回可直接交给 endpoint.RegisterBuiltin 的处理函数.
func (m *Module) BuiltinHandler() endpoint.BuiltinHandler {
	return func(call endpoint.BuiltinCall) endpoint.BuiltinResult {
		switch call.MethodID {
		case MethodListGrants:
			return m.listGrants(call.Payload)
		case MethodSetGrantState:
			return m.setGrantState(call.Payload)
		default:
			// fail closed: 没实现的方法就是不存在. 回一个空列表会让界面
			// 以为这台机器上没有任何权限需要授权
			return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
		}
	}
}

func (m *Module) ready() bool {
	return m != nil && m.definitions != nil && m.packages != nil && m.grants != nil
}

// listGrants 列出各包的 USER_CONSENT 权限与当前状态.
//
// 一次读定 Catalog Snapshot, 整份响应来自同一个修订版: 分两次读会让响应里混进
// 两个修订版的内容, 出现"列出了一个刚被卸载的包的权限"这类无法复现的结果
func (m *Module) listGrants(payload []byte) endpoint.BuiltinResult {
	if !m.ready() {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE}
	}

	req := &permissionv1.ListGrantsRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		// 解不开的请求是调用方的错. 回 INVALID_ARGUMENT 而不是当成空请求
		// 列出全部 —— 那会把一次编码错误变成一次全量列举
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT}
	}

	snap := m.definitions.Current()
	out := &permissionv1.GrantList{}
	for _, entry := range m.packages.List() {
		packageID := entry.Manifest.PackageID
		if filter := req.GetPackageId(); filter != "" && filter != packageID {
			continue
		}
		permissions := m.consentGrantsOf(snap, entry)
		if len(permissions) == 0 {
			// 一条可授予权限都没有的包不进列表: 设置页里列一个点进去
			// 空无一物的条目, 对用户是纯噪音
			continue
		}
		out.Packages = append(out.Packages, &permissionv1.PackageGrants{
			PackageId:   packageID,
			Label:       entry.Manifest.Label,
			Permissions: permissions,
		})
	}
	// 顺序确定, 否则设置页里的条目每次刷新都在跳
	sort.Slice(out.Packages, func(i, j int) bool {
		return out.Packages[i].GetPackageId() < out.Packages[j].GetPackageId()
	})

	wire, err := proto.Marshal(out)
	if err != nil {
		if m.log != nil {
			m.log.Warn("permissionadmin: marshal grant list failed", "err", err)
		}
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL}
	}
	return endpoint.BuiltinResult{Payload: wire, Code: ipcv1.StatusCode_STATUS_CODE_OK}
}

// consentGrantsOf 投影一个包的 USER_CONSENT 权限.
//
// 只看 GrantedPermissions 而不是 manifest 申请的那份: 前者是安装期裁决之后
// 【真正拿到】的集合. 列一条裁决没批的权限, 等于给用户一个打开也不生效的开关
func (m *Module) consentGrantsOf(
	snap *catalog.Snapshot, entry pkgregistry.Entry,
) []*permissionv1.PermissionGrant {
	var out []*permissionv1.PermissionGrant
	for _, permissionID := range entry.GrantedPermissions {
		definition, ok := snap.Permission(permissionID)
		if !ok || definition.GrantMode != ipcv1.GrantMode_GRANT_MODE_USER_CONSENT {
			// 其它授予模式没有运行期状态可言, 列出来只会给用户一排拨不动的开关
			continue
		}
		out = append(out, &permissionv1.PermissionGrant{
			PermissionId: permissionID,
			// 文案由内核给出而不是界面写死: 第三方包可以定义自己的权限,
			// 界面不可能预先知道它们的文案
			DisplayName: &ipcv1.LocalizedText{
				ZhCn: definition.DisplayNameZhCN, En: definition.DisplayNameEN,
			},
			Description: &ipcv1.LocalizedText{
				ZhCn: definition.DescriptionZhCN, En: definition.DescriptionEN,
			},
			RiskClass: definition.RiskClass,
			State:     wireGrantState(m.grants.GrantStateOf(entry.Manifest.PackageID, permissionID)),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].GetPermissionId() < out[j].GetPermissionId()
	})
	return out
}

// setGrantState 改一条 USER_CONSENT 权限的运行期状态.
func (m *Module) setGrantState(payload []byte) endpoint.BuiltinResult {
	if !m.ready() {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE}
	}

	req := &permissionv1.SetGrantStateRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT}
	}
	if req.GetPackageId() == "" || req.GetPermissionId() == "" {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT}
	}

	state, ok := kernelGrantState(req.GetState())
	if !ok {
		// UNSPECIFIED 是没填; NOT_REQUESTED 是"回到从没问过", 那不是用户能做的
		// 决定 —— 想收回就用 DENIED
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT}
	}

	if err := m.grants.SetRuntimeState(req.GetPackageId(), req.GetPermissionId(), state); err != nil {
		if m.log != nil {
			m.log.Warn("permissionadmin: set grant state failed",
				"package", req.GetPackageId(), "permission", req.GetPermissionId(), "err", err)
		}
		// 失败的原因都是"这条权限现在不该被改": 不是 USER_CONSENT, 包已卸载,
		// 或安装期就没拿到. 三者都是调用方拿着一份过期视图在操作,
		// FAILED_PRECONDITION 比 INTERNAL 更能说明该怎么办 (重新 ListGrants)
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION}
	}

	// 回一个显式的现状而不是空响应: 界面拿回来的应该是【现在的事实】,
	// 而不是它自己刚才请求的那个值
	resp := &permissionv1.SetGrantStateResponse{
		State: wireGrantState(m.grants.GrantStateOf(req.GetPackageId(), req.GetPermissionId())),
	}
	wire, err := proto.Marshal(resp)
	if err != nil {
		if m.log != nil {
			m.log.Warn("permissionadmin: marshal set-grant response failed", "err", err)
		}
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL}
	}
	return endpoint.BuiltinResult{Payload: wire, Code: ipcv1.StatusCode_STATUS_CODE_OK}
}

// wireGrantState 把内核状态投影到 wire 枚举.
//
// 逐值显式映射而不是数值转换: 两个枚举【零值不同】—— 内核的 0 是 NotRequested,
// wire 的 0 是 UNSPECIFIED (proto3 分不出"没填"和"填了零值"). 直接转换会把
// "还没问过用户"送成"没填"
func wireGrantState(state permission.GrantState) permissionv1.GrantState {
	switch state {
	case permission.GrantStateGranted:
		return permissionv1.GrantState_GRANT_STATE_GRANTED
	case permission.GrantStateDenied:
		return permissionv1.GrantState_GRANT_STATE_DENIED
	case permission.GrantStateDeniedPermanent:
		return permissionv1.GrantState_GRANT_STATE_DENIED_PERMANENT
	case permission.GrantStateNotRequested:
		return permissionv1.GrantState_GRANT_STATE_NOT_REQUESTED
	default:
		return permissionv1.GrantState_GRANT_STATE_UNSPECIFIED
	}
}

// kernelGrantState 把 wire 枚举收回内核状态. 第二个返回值为 false 表示这个取值
// 不是调用方可以设置的目标状态
func kernelGrantState(state permissionv1.GrantState) (permission.GrantState, bool) {
	switch state {
	case permissionv1.GrantState_GRANT_STATE_GRANTED:
		return permission.GrantStateGranted, true
	case permissionv1.GrantState_GRANT_STATE_DENIED:
		return permission.GrantStateDenied, true
	case permissionv1.GrantState_GRANT_STATE_DENIED_PERMANENT:
		return permission.GrantStateDeniedPermanent, true
	default:
		return permission.GrantStateNotRequested, false
	}
}
