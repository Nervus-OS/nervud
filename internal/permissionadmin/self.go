// 本文件是 nervus.interface.permission.self 的内建实现: "我有没有这条权限".
//
// # 它补的缺口
//
// 应用在调一个需要敏感权限的方法之前, 需要能先问一句 —— 对应 Android 的
// checkSelfPermission. 没有它, 应用只有两条路: 盲调一次然后从
// PERMISSION_DENIED 里推断 (对有副作用的方法根本不能这么试), 或者干脆假设
// 自己有权限, 让功能在用户面前静默失败.
//
// # 为什么与 .admin 同一个 Module 但不同 interface_id
//
// 两者读的是同一份状态 (permission.Registry), 实现者确实是同一处代码 ——
// 所以共用一个 Module 与一个内建组件 (builtin.permission).
//
// 但门槛差着一个数量级: .admin 要 perm.permission.admin (SYSTEM_ONLY +
// platform-release 签名), 而自查【无门槛】. Catalog 的模型里一个 interface_id
// 只有一份门槛, 要让门槛不同就必须是两个接口.
//
// # 无门槛的边界在哪
//
// 目标包恒为调用方自己: 请求里没有 package_id 字段, 身份取自
// BuiltinCall.Caller (那是 SO_PEERCRED 认出来的, 不是请求里的自述). 因此本接口
// 不构成"查任意包授权状态"的无门槛入口 —— 那属于 .admin.
//
// 这个区分是实质性的: 权限布局是一份侦察情报. "这台机器上哪个应用拿到了
// 摄像头和运动控制"对攻击者有直接价值, 而"我自己有没有"对调用方本来就是
// 可知的 (它随时能试着调一次).
package permissionadmin

import (
	"sort"

	permissionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/permissionv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

// SelfBuiltinInterfaceID 是自查接口的 ID.
//
// 必须与 catalog bootstrap 里那次 bootstrapInterface 调用一致 —— 那里定门槛.
const SelfBuiltinInterfaceID = catalog.InterfacePermissionSelf

// 方法号取自生成代码的枚举值, 不在本地重抄字面量: 抄一份会悄悄过期.
const MethodCheckSelf = uint32(
	permissionv1.PermissionSelfMethod_PERMISSION_SELF_METHOD_CHECK)

// maxCheckPermissions 是一次 Check 能问的权限条数上限.
//
// 有上限而不是照单全收: 本方法【无门槛】, 任何应用都能调, 而每条都要查一次
// Catalog 定义与授予状态. 没有上限的话, 一个请求里塞十万个权限 ID 就是一次
// 廉价的放大攻击 —— 攻击方只付一个请求的代价.
//
// 100 远高于任何真实用途 (bootstrap 里 USER_CONSENT 权限总数只有个位数),
// 因此它拦不到正常调用方, 只拦明显异常的请求.
const maxCheckPermissions = 100

// SelfBuiltinHandler 返回可直接交给 endpoint.RegisterBuiltin 的处理函数.
//
// 与 BuiltinHandler 分开注册: 两者是两个 interface_id, endpoint 按接口路由.
func (m *Module) SelfBuiltinHandler() endpoint.BuiltinHandler {
	return func(call endpoint.BuiltinCall) endpoint.BuiltinResult {
		switch call.MethodID {
		case MethodCheckSelf:
			return m.checkSelf(call.Caller, call.Payload)
		default:
			// fail closed: 没实现的方法就是不存在
			return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
		}
	}
}

// checkSelf 回答调用方对一批权限各是什么状态.
//
// 一次读定 Catalog Snapshot, 整份响应来自同一个修订版: 分多次读会让响应里混进
// 两个修订版的内容, 出现"同一次回答里 A 权限按新定义算, B 按旧定义算"这种
// 无法复现的结果.
func (m *Module) checkSelf(caller identity.Caller, payload []byte) endpoint.BuiltinResult {
	if !m.ready() {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE}
	}
	// 空 PackageID 必须拒而不是当成"匿名调用方"往下走: 那会让整份回答变成
	// "对某个不存在的包的查询", 每一条都是 granted=false —— 一个看起来正常的
	// 否定答复, 而真实原因是握手没认出调用方. 这条路正常走不到 (endpoint 只
	// 把认出身份的连接交下来), 但 fail closed 的方向必须写明
	if caller.PackageID == "" {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED}
	}

	req := &permissionv1.CheckSelfPermissionRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		// 解不开的请求是调用方的错. 不当成空请求 —— 那会把一次编码错误
		// 变成一次看起来成功的空回答
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT}
	}
	if len(req.GetPermissionIds()) > maxCheckPermissions {
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT}
	}

	snap := m.definitions.Current()
	if snap == nil {
		// 读不到定义时不能回一份"全都没有"的清单: 那会让应用以为用户拒绝了
		// 一切, 从而走进"引导用户去设置"的死路, 而真实原因是内核暂时读不到
		// Catalog
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE}
	}

	installed := m.installedGrantSetOf(caller.PackageID)

	out := &permissionv1.CheckSelfPermissionResult{}
	seen := make(map[string]struct{}, len(req.GetPermissionIds()))
	for _, permissionID := range req.GetPermissionIds() {
		if permissionID == "" {
			continue
		}
		// 去重: 重复项只答一次. 调用方按 permission_id 索引结果
		// (proto 注释里写明了不要按下标)
		if _, dup := seen[permissionID]; dup {
			continue
		}
		seen[permissionID] = struct{}{}
		out.States = append(out.States,
			m.selfStateOf(snap, caller.PackageID, permissionID, installed))
	}
	// 顺序确定, 与请求无关: 一份稳定排序的回答让调用方的日志可比对
	sort.Slice(out.States, func(i, j int) bool {
		return out.States[i].GetPermissionId() < out.States[j].GetPermissionId()
	})

	wire, err := proto.Marshal(out)
	if err != nil {
		if m.log != nil {
			m.log.Warn("permissionadmin: marshal self-check failed",
				"package", caller.PackageID, "err", err)
		}
		return endpoint.BuiltinResult{Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL}
	}
	return endpoint.BuiltinResult{Payload: wire, Code: ipcv1.StatusCode_STATUS_CODE_OK}
}

// selfStateOf 算一条权限对某个包的三个事实: 能不能用, 运行期状态, 还值不值得申请.
func (m *Module) selfStateOf(
	snap *catalog.Snapshot,
	packageID string,
	permissionID string,
	installed map[string]struct{},
) *permissionv1.SelfPermissionState {
	state := &permissionv1.SelfPermissionState{PermissionId: permissionID}

	definition, defined := snap.Permission(permissionID)
	if !defined {
		// 未定义的权限 (拼错, 或来自一个已卸载的定义方): 回一条否定结果而不是
		// 让整次调用失败 —— 一个拼错的权限名不该让应用连别的几条都查不到.
		// requestable 为 false: 申请一条不存在的权限永远不会成功
		return state
	}

	// granted 取 AllowedAt 而不是自己拼: 那是内核授权判定的【同一处代码】,
	// 已经把三件事合起来算过 (在不在安装期集合里, 哪一档授予模式, USER_CONSENT
	// 的运行期状态是否 Granted, 以及系统软件的 consent 豁免).
	//
	// 在这里重算一份的后果是造出第二个真相源: 两边一旦不一致, 应用会看到
	// "自查说有, 实际调用被拒" —— 而那是最难查的一类故障, 因为两处代码单独看
	// 都是对的
	state.Granted = m.grants.AllowedAt(snap, packageID, permissionID)

	// 运行期状态只有 USER_CONSENT 那一档有意义. 其余留 UNSPECIFIED 而不是
	// NOT_REQUESTED: 后者会让应用以为"问一下就能有", 而 NORMAL 装上即生效,
	// PRIVILEGED / SYSTEM_ONLY 则不是用户能改的
	isConsent := definition.GrantMode == ipcv1.GrantMode_GRANT_MODE_USER_CONSENT
	if isConsent {
		state.State = wireGrantState(m.grants.GrantStateOf(packageID, permissionID))
	}

	state.Requestable = requestable(isConsent, installed, permissionID, state)
	return state
}

// requestable 判断"再去申请一次"还有没有意义.
//
// 四条否决理由, 每条对应一类真实情形:
//
//	不是 USER_CONSENT       别的档不由用户决定, 弹窗问了也改不了
//	不在安装期授予集合里     安装期裁决没批 (信任不够/签名角色不对/来源不对),
//	                        或者本包压根没在 manifest 里申请过它. 用户点头
//	                        不能凭空补上 —— SetRuntimeState 自带这道校验
//	已经是 Granted          已经有了, 再申请只是白弹一次窗
//	DENIED_PERMANENT        用户已永久拒绝. 弹窗不会出现, 结果也不会变
//
// 【这个字段存在的意义是掐断一类循环】: 没有它, 应用看到 granted=false 只能去
// 申请, 而申请对上述任一情形都注定失败且不改变 granted, 于是重试 —— 一个开机
// 就开始空转, 且每次都可能弹一次窗的循环.
func requestable(
	isConsent bool,
	installed map[string]struct{},
	permissionID string,
	state *permissionv1.SelfPermissionState,
) bool {
	if !isConsent {
		return false
	}
	if _, ok := installed[permissionID]; !ok {
		return false
	}
	if state.GetGranted() {
		return false
	}
	return state.GetState() != permissionv1.GrantState_GRANT_STATE_DENIED_PERMANENT
}

// installedGrantSetOf 取某个包安装期【真正拿到】的权限集合.
//
// 用 Entry.GrantedPermissions 而不是 manifest.Permissions: 前者是安装期裁决之后
// 的结论, 后者只是申请. 按申请算的话, 一个在 manifest 里多写一行的包就会得到
// requestable = true, 而它去申请必然失败 —— 正是本字段要避免的那个循环.
//
// 包不存在时返回空集合 (不是 nil 判断的特例): 那时每条权限的 requestable 都是
// false, 与"这个包什么都没拿到"一致
func (m *Module) installedGrantSetOf(packageID string) map[string]struct{} {
	for _, entry := range m.packages.List() {
		if entry.Manifest.PackageID != packageID {
			continue
		}
		out := make(map[string]struct{}, len(entry.GrantedPermissions))
		for _, p := range entry.GrantedPermissions {
			out[p] = struct{}{}
		}
		return out
	}
	return map[string]struct{}{}
}

// 编译期确认 *permission.Registry 满足扩展后的 GrantReader.
//
// 写在这里而不是靠 main.go 的装配来暴露: 装配失败的信息是一句
// "cannot use permReg as GrantReader", 而这里能指明是哪个接口在要求它
var _ GrantReader = (*permission.Registry)(nil)
