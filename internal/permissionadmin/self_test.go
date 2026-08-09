package permissionadmin

import (
	"testing"

	permissionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/permissionv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// rawCheck 发一次 Check 并原样回结果, 供要断言错误码的用例使用.
func rawCheck(
	t *testing.T, m *Module, caller identity.Caller, req *permissionv1.CheckSelfPermissionRequest,
) endpoint.BuiltinResult {
	t.Helper()
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return m.SelfBuiltinHandler()(endpoint.BuiltinCall{
		MethodID: MethodCheckSelf,
		Payload:  payload,
		Caller:   caller,
	})
}

// callCheck 发一次 Check 并要求成功, 结果按权限 ID 索引.
//
// callerPackage 是内核认出来的调用方身份 —— 本接口的目标包【完全】由它决定,
// 请求里没有 package_id 字段.
//
// 按 ID 索引而不是按下标: 请求里的重复项会被去重, 下标随即对不上.
func callCheck(
	t *testing.T, m *Module, callerPackage string, permissionIDs ...string,
) map[string]*permissionv1.SelfPermissionState {
	t.Helper()
	res := rawCheck(t, m, identity.Caller{PackageID: callerPackage},
		&permissionv1.CheckSelfPermissionRequest{PermissionIds: permissionIDs})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_OK {
		t.Fatalf("Check code = %v, want OK", res.Code)
	}
	out := &permissionv1.CheckSelfPermissionResult{}
	if err := proto.Unmarshal(res.Payload, out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	byID := make(map[string]*permissionv1.SelfPermissionState, len(out.GetStates()))
	for _, s := range out.GetStates() {
		byID[s.GetPermissionId()] = s
	}
	return byID
}

func grantedState(pkg, perm string, state permission.GrantState) *fakeGrants {
	return &fakeGrants{states: map[[2]string]permission.GrantState{
		{pkg, perm}: state,
	}}
}

// TestCheckSelf_GrantedFollowsRuntimeState 钉住 granted 跟着运行期状态走.
//
// 这是自查的基本用途: 用户在权限管理里关掉一条, 应用下一次自查就该看到 false,
// 而不是继续按"我有权限"往下走, 再被 PERMISSION_DENIED 打回.
func TestCheckSelf_GrantedFollowsRuntimeState(t *testing.T) {
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry("com.example.cam", "相机", permStorageUser),
	}}
	grants := grantedState("com.example.cam", permStorageUser, permission.GrantStateGranted)
	m := newTestModule(t, lister, grants)

	got := callCheck(t, m, "com.example.cam", permStorageUser)[permStorageUser]
	if got == nil {
		t.Fatal("缺少 " + permStorageUser + " 的结果")
	}
	if !got.GetGranted() {
		t.Error("granted = false, want true (运行期状态是 Granted)")
	}
	if got.GetState() != permissionv1.GrantState_GRANT_STATE_GRANTED {
		t.Errorf("state = %v, want GRANTED", got.GetState())
	}
	// 已经有了, 再申请只是白弹一次窗
	if got.GetRequestable() {
		t.Error("requestable = true, want false (已经是 Granted)")
	}
}

// TestCheckSelf_NotRequestedIsRequestable: 从没问过 + 在安装期授予集合里 =
// 正该去申请. 这是 Android 式流程的入口条件.
func TestCheckSelf_NotRequestedIsRequestable(t *testing.T) {
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry("com.example.cam", "相机", permStorageUser),
	}}
	m := newTestModule(t, lister, &fakeGrants{})

	got := callCheck(t, m, "com.example.cam", permStorageUser)[permStorageUser]
	if got.GetGranted() {
		t.Error("granted = true, want false (还没问过用户)")
	}
	if got.GetState() != permissionv1.GrantState_GRANT_STATE_NOT_REQUESTED {
		t.Errorf("state = %v, want NOT_REQUESTED", got.GetState())
	}
	if !got.GetRequestable() {
		t.Error("requestable = false, want true (申请它是有意义的)")
	}
}

// TestCheckSelf_RequestableFalseCases 钉住"申请注定失败"的那几类, 逐条给出理由.
//
// 【这个字段存在的意义是掐断一类循环】: 没有它, 应用看到 granted=false 只能去
// 申请, 而申请对这些情形注定失败且不改变 granted, 于是重试 —— 一个开机就开始
// 空转, 每次都可能弹一次窗的循环.
func TestCheckSelf_RequestableFalseCases(t *testing.T) {
	const pkg = "com.example.app"

	tests := []struct {
		name       string
		granted    []string // 安装期真正拿到的
		state      permission.GrantState
		permission string
		wantState  permissionv1.GrantState
	}{
		{
			// 安装期裁决没批 (信任不够/签名角色不对), 或压根没在 manifest 里申请过.
			// 用户点头不能凭空补上 —— SetRuntimeState 自带这道校验
			name:       "不在安装期授予集合里",
			granted:    []string{permStorageUser},
			permission: permMotionControl,
			wantState:  permissionv1.GrantState_GRANT_STATE_NOT_REQUESTED,
		},
		{
			// 用户已永久拒绝: 弹窗不会出现, 结果也不会变. 应当引导用户去权限
			// 管理界面, 而不是重试
			name:       "已永久拒绝",
			granted:    []string{permStorageUser},
			state:      permission.GrantStateDeniedPermanent,
			permission: permStorageUser,
			wantState:  permissionv1.GrantState_GRANT_STATE_DENIED_PERMANENT,
		},
		{
			// NORMAL 装上即生效, 没有运行期状态可言. state 留 UNSPECIFIED 而不是
			// NOT_REQUESTED —— 后者会让应用以为"问一下就能有"
			name:       "不是 USER_CONSENT",
			granted:    []string{permPkgQuery},
			permission: permPkgQuery,
			wantState:  permissionv1.GrantState_GRANT_STATE_UNSPECIFIED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lister := &fakeLister{entries: []pkgregistry.Entry{
				entry(pkg, "应用", tc.granted...),
			}}
			grants := grantedState(pkg, tc.permission, tc.state)
			m := newTestModule(t, lister, grants)

			got := callCheck(t, m, pkg, tc.permission)[tc.permission]
			if got == nil {
				t.Fatalf("缺少 %s 的结果", tc.permission)
			}
			if got.GetRequestable() {
				t.Error("requestable = true, want false")
			}
			if got.GetState() != tc.wantState {
				t.Errorf("state = %v, want %v", got.GetState(), tc.wantState)
			}
		})
	}
}

// TestCheckSelf_TargetIsAlwaysTheCaller 钉住"只能查自己".
//
// 目标包由 BuiltinCall.Caller 决定, 请求里没有 package_id. 因此同一份请求由
// 两个不同调用方发出, 得到的是各自的答案 —— 一个包无从窥探另一个包的授权状态.
//
// 这不只是隐私: 权限布局是一份侦察情报. "这台机器上哪个应用拿到了摄像头和
// 运动控制"对攻击者有直接价值.
func TestCheckSelf_TargetIsAlwaysTheCaller(t *testing.T) {
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry("com.example.has", "有权限的", permStorageUser),
		entry("com.example.none", "没权限的"),
	}}
	grants := grantedState("com.example.has", permStorageUser, permission.GrantStateGranted)
	m := newTestModule(t, lister, grants)

	mine := callCheck(t, m, "com.example.has", permStorageUser)[permStorageUser]
	if !mine.GetGranted() {
		t.Error("持有者自查 granted = false, want true")
	}

	// 同一条权限, 换一个调用方: 它看到的是自己的状态, 而不是别人的
	theirs := callCheck(t, m, "com.example.none", permStorageUser)[permStorageUser]
	if theirs.GetGranted() {
		t.Error("另一个包看到 granted = true —— 它不该看得见别人的授权状态")
	}
	if theirs.GetRequestable() {
		t.Error("另一个包看到 requestable = true, want false (它没在安装期拿到这条)")
	}
}

// TestCheckSelf_UnknownPermissionDoesNotFailTheCall: 一个拼错的权限名不该让应用
// 连别的几条都查不到. 回一条否定结果, 而不是整次失败.
func TestCheckSelf_UnknownPermissionDoesNotFailTheCall(t *testing.T) {
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry("com.example.cam", "相机", permStorageUser),
	}}
	grants := grantedState("com.example.cam", permStorageUser, permission.GrantStateGranted)
	m := newTestModule(t, lister, grants)

	got := callCheck(t, m, "com.example.cam", "perm.does.not.exist", permStorageUser)

	unknown := got["perm.does.not.exist"]
	if unknown == nil {
		t.Fatal("未定义的权限也该有一条结果")
	}
	if unknown.GetGranted() || unknown.GetRequestable() {
		t.Errorf("未定义权限 granted=%v requestable=%v, 都该是 false",
			unknown.GetGranted(), unknown.GetRequestable())
	}
	// 关键: 同一次调用里正常那条照样答出来了
	if real := got[permStorageUser]; real == nil || !real.GetGranted() {
		t.Error("正常那条权限被未定义的那条带累了")
	}
}

// TestCheckSelf_DeduplicatesAndSorts: 重复项只答一次, 顺序确定.
func TestCheckSelf_DeduplicatesAndSorts(t *testing.T) {
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry("com.example.app", "应用", permStorageUser, permMotionControl),
	}}
	m := newTestModule(t, lister, &fakeGrants{})

	res := rawCheck(t, m, identity.Caller{PackageID: "com.example.app"},
		&permissionv1.CheckSelfPermissionRequest{PermissionIds: []string{
			permStorageUser, permMotionControl, permStorageUser, "", permStorageUser,
		}})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_OK {
		t.Fatalf("code = %v, want OK", res.Code)
	}
	out := &permissionv1.CheckSelfPermissionResult{}
	if err := proto.Unmarshal(res.Payload, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out.GetStates()) != 2 {
		t.Fatalf("states = %d, want 2 (去重后, 空串丢弃)", len(out.GetStates()))
	}
	// 排序确定: motion < storage
	if a, b := out.GetStates()[0].GetPermissionId(), out.GetStates()[1].GetPermissionId(); a > b {
		t.Errorf("结果未按权限 ID 排序: %q 在 %q 之前", a, b)
	}
}

// TestCheckSelf_EmptyRequestIsOK: 一个不申请任何敏感权限的应用照样能调它
// (通常是一段与权限数量无关的通用启动代码). 空列表回空列表, 不是错误.
func TestCheckSelf_EmptyRequestIsOK(t *testing.T) {
	m := newTestModule(t, &fakeLister{}, &fakeGrants{})

	res := rawCheck(t, m, identity.Caller{PackageID: "com.example.app"},
		&permissionv1.CheckSelfPermissionRequest{})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_OK {
		t.Fatalf("code = %v, want OK", res.Code)
	}
	out := &permissionv1.CheckSelfPermissionResult{}
	if err := proto.Unmarshal(res.Payload, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.GetStates()) != 0 {
		t.Errorf("states = %d, want 0", len(out.GetStates()))
	}
}

// TestCheckSelf_RejectsUnauthenticatedCaller 钉住 fail-closed 的方向.
//
// 空 PackageID 必须拒而不是当成"匿名调用方"往下走: 那会让整份回答变成对一个
// 不存在的包的查询, 每条都是 granted=false —— 一个看起来正常的否定答复, 而
// 真实原因是握手没认出调用方.
func TestCheckSelf_RejectsUnauthenticatedCaller(t *testing.T) {
	m := newTestModule(t, &fakeLister{}, &fakeGrants{})

	res := rawCheck(t, m, identity.Caller{},
		&permissionv1.CheckSelfPermissionRequest{PermissionIds: []string{permStorageUser}})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED {
		t.Fatalf("code = %v, want UNAUTHENTICATED", res.Code)
	}
}

// TestCheckSelf_RejectsOversizedRequest: 本方法【无门槛】, 任何应用都能调,
// 而每条都要查一次 Catalog 定义与授予状态. 没有上限的话, 一个请求里塞十万个
// 权限 ID 就是一次廉价的放大攻击.
func TestCheckSelf_RejectsOversizedRequest(t *testing.T) {
	m := newTestModule(t, &fakeLister{}, &fakeGrants{})

	ids := make([]string, maxCheckPermissions+1)
	for i := range ids {
		ids[i] = permStorageUser
	}
	res := rawCheck(t, m, identity.Caller{PackageID: "com.example.app"},
		&permissionv1.CheckSelfPermissionRequest{PermissionIds: ids})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Fatalf("code = %v, want INVALID_ARGUMENT", res.Code)
	}
}

// TestCheckSelf_UnknownMethodIsNotFound: fail closed —— 没实现的方法就是不存在.
func TestCheckSelf_UnknownMethodIsNotFound(t *testing.T) {
	m := newTestModule(t, &fakeLister{}, &fakeGrants{})

	res := m.SelfBuiltinHandler()(endpoint.BuiltinCall{
		MethodID: 9999,
		Caller:   identity.Caller{PackageID: "com.example.app"},
	})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v, want NOT_FOUND", res.Code)
	}
}
