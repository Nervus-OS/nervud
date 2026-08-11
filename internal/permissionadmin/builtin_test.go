package permissionadmin

import (
	"testing"

	permissionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/permissionv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// 三条内核 bootstrap 权限, 各代表一类:
//
//	permStorageUser / permMotionControl  USER_CONSENT - 有运行期状态, 该出现
//	permPkgQuery                         NORMAL       - 没有运行期状态, 不该出现
const (
	permStorageUser   = "perm.storage.user"
	permMotionControl = "perm.motion.control"
	permPkgQuery      = "perm.pkg.query"
)

type fakeLister struct{ entries []pkgregistry.Entry }

func (f *fakeLister) List() []pkgregistry.Entry { return f.entries }

type fakeGrants struct {
	states map[[2]string]permission.GrantState
	setErr error
	sets   [][3]string
	// exempt 是"系统软件"集合, 对应 permission.Grant.ConsentExempt.
	//
	// 必须建模它, 不能只留运行期状态: 豁免与授予在 wire 上是两个字段
	// (state 与 effective_granted), 而它们【只在豁免时不一致】—— 一个不建模
	// 豁免的 fake 永远测不到那个分歧, 而那正是本包出过的 bug.
	exempt map[string]struct{}
}

func (f *fakeGrants) GrantStateOf(pkg, perm string) permission.GrantState {
	if f.states == nil {
		return permission.GrantStateNotRequested
	}
	return f.states[[2]string{pkg, perm}]
}

// AllowedAt 是 permission.self 的 granted 与 ListGrants 的 effective_granted
// 两者共同的来源.
//
// fake 里按"豁免 or 运行期状态"判定, 与真实 Registry.AllowedAt 的 USER_CONSENT
// 分支同构: 本包的测试用的权限都是 USER_CONSENT, 而安装期集合与授予模式那两道
// 归 internal/permission 的测试管 —— 在这里复刻一份只会让 fake 与真实实现同时
// 漂移.
//
// 【豁免这一支必须建模】: 它是 state 与 effective_granted 唯一会不一致的地方.
func (f *fakeGrants) AllowedAt(_ *catalog.Snapshot, pkg, perm string) bool {
	if _, ok := f.exempt[pkg]; ok {
		return true
	}
	return f.GrantStateOf(pkg, perm) == permission.GrantStateGranted
}

func (f *fakeGrants) SetRuntimeState(pkg, perm string, state permission.GrantState) error {
	f.sets = append(f.sets, [3]string{pkg, perm, string(rune('0' + int(state)))})
	if f.setErr != nil {
		return f.setErr
	}
	if f.states == nil {
		f.states = map[[2]string]permission.GrantState{}
	}
	f.states[[2]string{pkg, perm}] = state
	return nil
}

func entry(packageID, label string, granted ...string) pkgregistry.Entry {
	return pkgregistry.Entry{
		Manifest:           pkgregistry.Manifest{PackageID: packageID, Label: label},
		GrantedPermissions: granted,
	}
}

func newTestModule(t *testing.T, lister *fakeLister, grants *fakeGrants) *Module {
	t.Helper()
	definitions, err := catalog.NewDefaultRegistry()
	if err != nil {
		t.Fatalf("new catalog: %v", err)
	}
	return New(definitions, lister, grants, nil)
}

func callList(t *testing.T, m *Module, req *permissionv1.ListGrantsRequest) *permissionv1.GrantList {
	t.Helper()
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	res := m.BuiltinHandler()(endpoint.BuiltinCall{MethodID: MethodListGrants, Payload: payload})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_OK {
		t.Fatalf("ListGrants code = %v, want OK", res.Code)
	}
	out := &permissionv1.GrantList{}
	if err := proto.Unmarshal(res.Payload, out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return out
}

// TestListGrants_OnlyUserConsent 钉住"列表里只出现拨得动的开关".
//
// 非 USER_CONSENT 的权限没有运行期状态可言, 列出来就是一排拨不动的开关;
// 一条可授予权限都没有的包列出来则是一个点进去空无一物的条目
func TestListGrants_OnlyUserConsent(t *testing.T) {
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry("com.example.cam", "相机", permStorageUser, permPkgQuery),
		entry("com.example.plain", "纯查询", permPkgQuery), // 一条 USER_CONSENT 都没有
	}}
	m := newTestModule(t, lister, &fakeGrants{})

	out := callList(t, m, &permissionv1.ListGrantsRequest{})

	if len(out.GetPackages()) != 1 {
		t.Fatalf("packages = %d, want 1 (纯查询包不该出现)", len(out.GetPackages()))
	}
	pkg := out.GetPackages()[0]
	if pkg.GetPackageId() != "com.example.cam" || pkg.GetLabel() != "相机" {
		t.Fatalf("package = %q/%q", pkg.GetPackageId(), pkg.GetLabel())
	}
	if len(pkg.GetPermissions()) != 1 {
		t.Fatalf("permissions = %+v, want only %s", pkg.GetPermissions(), permStorageUser)
	}
	got := pkg.GetPermissions()[0]
	if got.GetPermissionId() != permStorageUser {
		t.Fatalf("permission = %q, want %q", got.GetPermissionId(), permStorageUser)
	}
	// 文案由内核给出: 界面不可能预先知道第三方包自定义权限的文案
	if got.GetDisplayName().GetZhCn() == "" || got.GetDescription().GetZhCn() == "" {
		t.Fatalf("中文文案为空: name=%q desc=%q",
			got.GetDisplayName().GetZhCn(), got.GetDescription().GetZhCn())
	}
	if got.GetDisplayName().GetZhCn() == got.GetDescription().GetZhCn() {
		t.Fatalf("标题与说明相同 (%q): 授权屏上等于没有说明",
			got.GetDisplayName().GetZhCn())
	}
}

// TestListGrants_NeverRequestedIsNotUnspecified 钉住两个枚举零值不同这件事.
//
// 内核的零值是 NotRequested, wire 的零值是 UNSPECIFIED. 直接做数值转换会把
// "还没问过用户"送成"没填", 而界面对这两者的处理完全不同
func TestListGrants_NeverRequestedIsNotUnspecified(t *testing.T) {
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry("com.example.cam", "相机", permStorageUser),
	}}
	m := newTestModule(t, lister, &fakeGrants{}) // 空 states = 从没问过

	out := callList(t, m, &permissionv1.ListGrantsRequest{})
	state := out.GetPackages()[0].GetPermissions()[0].GetState()
	if state != permissionv1.GrantState_GRANT_STATE_NOT_REQUESTED {
		t.Fatalf("state = %v, want NOT_REQUESTED", state)
	}
}

// TestListGrants_SystemSoftwareIsEffectivelyGranted 钉住 state 与
// effective_granted 对系统软件【必须不一致】.
//
// 这是本包出过的一个 bug: 界面只看 state, 而系统软件走 consent 豁免 ——
// 豁免不伪造授予记录, 所以 state 恒为 NOT_REQUESTED, 而 AllowedAt 恒为 true.
// 于是文件管理器的"用户文件"开关显示关闭, 它却实际能读写用户目录:
// 开关与事实相反.
//
// 两个字段各自钉住, 不能只查一个: 只查 effective_granted 会漏掉"有人把 state
// 也一起改成 GRANTED"这种修法 —— 那会让"用户做过什么决定"这个事实消失, 而
// 普通应用要靠它区分"还没问过"与"问过被拒".
func TestListGrants_SystemSoftwareIsEffectivelyGranted(t *testing.T) {
	const systemPkg = "nervus.filemanager"
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry(systemPkg, "文件管理", permStorageUser),
	}}
	m := newTestModule(t, lister, &fakeGrants{
		// 豁免, 且【没有】任何运行期授予记录 —— 正是真实系统软件的状态
		exempt: map[string]struct{}{systemPkg: {}},
	})

	got := callList(t, m, &permissionv1.ListGrantsRequest{}).
		GetPackages()[0].GetPermissions()[0]

	if !got.GetEffectiveGranted() {
		t.Fatalf("effective_granted = false, want true: " +
			"系统软件走 consent 豁免, 实际能访问 —— 界面照这个字段显示开关")
	}
	if got.GetState() != permissionv1.GrantState_GRANT_STATE_NOT_REQUESTED {
		t.Fatalf("state = %v, want NOT_REQUESTED: 豁免【不伪造授予记录】, "+
			"改了这一点就丢掉了'用户做过什么决定'这个事实", got.GetState())
	}
}

// TestListGrants_EffectiveGrantedTracksUserDecision: 非豁免的普通应用两个字段
// 一致 —— 它没有豁免, 能不能用就等于用户同不同意
func TestListGrants_EffectiveGrantedTracksUserDecision(t *testing.T) {
	const appPkg = "com.example.cam"
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry(appPkg, "相机", permStorageUser),
	}}

	for _, tc := range []struct {
		name  string
		state permission.GrantState
		want  bool
	}{
		{"从没问过", permission.GrantStateNotRequested, false},
		{"用户同意", permission.GrantStateGranted, true},
		{"用户拒绝", permission.GrantStateDenied, false},
		{"永久拒绝", permission.GrantStateDeniedPermanent, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestModule(t, lister, &fakeGrants{
				states: map[[2]string]permission.GrantState{
					{appPkg, permStorageUser}: tc.state,
				},
			})
			got := callList(t, m, &permissionv1.ListGrantsRequest{}).
				GetPackages()[0].GetPermissions()[0]
			if got.GetEffectiveGranted() != tc.want {
				t.Fatalf("effective_granted = %v, want %v",
					got.GetEffectiveGranted(), tc.want)
			}
		})
	}
}

// TestListGrants_FilterAndOrder: package_id 过滤生效, 且输出顺序确定 ——
// 顺序不定会让设置页里的条目每次刷新都在跳
func TestListGrants_FilterAndOrder(t *testing.T) {
	lister := &fakeLister{entries: []pkgregistry.Entry{
		entry("com.z.app", "Z", permStorageUser),
		entry("com.a.app", "A", permMotionControl, permStorageUser),
	}}
	m := newTestModule(t, lister, &fakeGrants{})

	all := callList(t, m, &permissionv1.ListGrantsRequest{})
	if len(all.GetPackages()) != 2 {
		t.Fatalf("packages = %d, want 2", len(all.GetPackages()))
	}
	if all.GetPackages()[0].GetPackageId() != "com.a.app" {
		t.Fatalf("包顺序未按字典序: %q 在前", all.GetPackages()[0].GetPackageId())
	}
	perms := all.GetPackages()[0].GetPermissions()
	if len(perms) != 2 || perms[0].GetPermissionId() != permMotionControl {
		t.Fatalf("权限顺序未按字典序: %+v", perms)
	}

	only := callList(t, m, &permissionv1.ListGrantsRequest{PackageId: "com.z.app"})
	if len(only.GetPackages()) != 1 || only.GetPackages()[0].GetPackageId() != "com.z.app" {
		t.Fatalf("过滤失效: %+v", only.GetPackages())
	}
}

// TestSetGrantState_RejectsUnsettableStates: UNSPECIFIED 是没填, NOT_REQUESTED 是
// "回到从没问过" —— 后者不是用户能做的决定, 想收回用 DENIED
func TestSetGrantState_RejectsUnsettableStates(t *testing.T) {
	grants := &fakeGrants{}
	m := newTestModule(t, &fakeLister{}, grants)

	for _, state := range []permissionv1.GrantState{
		permissionv1.GrantState_GRANT_STATE_UNSPECIFIED,
		permissionv1.GrantState_GRANT_STATE_NOT_REQUESTED,
	} {
		payload, err := proto.Marshal(&permissionv1.SetGrantStateRequest{
			PackageId: "com.example.cam", PermissionId: permStorageUser, State: state,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		res := m.BuiltinHandler()(endpoint.BuiltinCall{
			MethodID: MethodSetGrantState, Payload: payload})
		if res.Code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
			t.Fatalf("state=%v code = %v, want INVALID_ARGUMENT", state, res.Code)
		}
	}
	if len(grants.sets) != 0 {
		t.Fatalf("不该落任何状态, 实际 %+v", grants.sets)
	}
}

// TestSetGrantState_ReturnsActualState: 回的是【现在的事实】而不是请求里那个值
func TestSetGrantState_ReturnsActualState(t *testing.T) {
	grants := &fakeGrants{}
	m := newTestModule(t, &fakeLister{}, grants)

	payload, err := proto.Marshal(&permissionv1.SetGrantStateRequest{
		PackageId:    "com.example.cam",
		PermissionId: permStorageUser,
		State:        permissionv1.GrantState_GRANT_STATE_GRANTED,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res := m.BuiltinHandler()(endpoint.BuiltinCall{
		MethodID: MethodSetGrantState, Payload: payload})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_OK {
		t.Fatalf("code = %v, want OK", res.Code)
	}
	out := &permissionv1.SetGrantStateResponse{}
	if err := proto.Unmarshal(res.Payload, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.GetState() != permissionv1.GrantState_GRANT_STATE_GRANTED {
		t.Fatalf("state = %v, want GRANTED", out.GetState())
	}
}

// TestBuiltin_FailsClosedWithoutDependencies: 依赖没接线时一律 UNAVAILABLE.
// 回空列表会让界面把"查不到"显示成"没有权限需要授权"
func TestBuiltin_FailsClosedWithoutDependencies(t *testing.T) {
	m := New(nil, nil, nil, nil)
	for _, method := range []uint32{MethodListGrants, MethodSetGrantState} {
		res := m.BuiltinHandler()(endpoint.BuiltinCall{MethodID: method})
		if res.Code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
			t.Fatalf("method %d code = %v, want UNAVAILABLE", method, res.Code)
		}
	}
}

// TestBuiltin_UnknownMethodIsNotFound: 没实现的方法就是不存在
func TestBuiltin_UnknownMethodIsNotFound(t *testing.T) {
	m := newTestModule(t, &fakeLister{}, &fakeGrants{})
	res := m.BuiltinHandler()(endpoint.BuiltinCall{MethodID: 9999})
	if res.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v, want NOT_FOUND", res.Code)
	}
}
