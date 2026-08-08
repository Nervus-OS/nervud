// 本文件是 permission 的权威运行期状态: Package ID -> 已授予权限集合,
// 供 ipc 的 Request 分派管线在裁决时查询
package permission

import (
	"fmt"
	"sync"
	"sync/atomic"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

// ErrDuplicatePackageID 一次 Replace 里两条 Grant 共用同一个 Package ID
var ErrDuplicatePackageID = fmt.Errorf("permission: duplicate package id in grant snapshot")

// Grant 是一个 Package 在某一时刻的全量已授予权限集合
//
// 这是 pkgregistry 推送给 permission 的投影单元, 与 identity.Package 投影
// identity 所需字段的方式一致 - 只带 permission 用得着的两个字段
type Grant struct {
	PackageID   string
	Permissions []string

	// ConsentExempt 表示这个包的 USER_CONSENT 权限不需要运行期同意.
	//
	// 判据是"系统软件": 随只读系统镜像发布 + Platform 信任 + 平台角色签名.
	// 由 pkgregistry 在投影时算出 (见 projectGrants), 不由本包判断 —— 包的
	// 来源与信任是 pkgregistry 的事实.
	//
	// # 为什么系统软件不走运行时同意
	//
	// 运行时同意问的是"你信不信这个第三方应用". 系统软件与内核同批发布, 同一
	// 条签名链, 用户装机时就已经接受了它们; 再问一遍不增加任何安全性 —— 用户
	// 唯一能做的选择是"同意", 否则文件管理器打不开文件, 设置装不了包.
	//
	// 真正需要这道门的是普通应用: 摄像头, 用户文件, 运动控制这类权限对它们
	// 必须逐次询问. 那条路走 GrantState, 与本字段无关.
	//
	// 注意它【不能】豁免安装期裁决: 系统软件照样只能拿到 IntersectAt 批准的
	// 权限集合, 本字段只跳过"用户此刻同不同意"这一问.
	ConsentExempt bool
}

// Registry 是 permission 的权威运行期状态
//
// 照抄 identity.Registry / pkgregistry.Registry 的写时复制 + 原子指针 +
// 全量替换范式: 读多写少 (每次连接的每次 Request 都要查, 只有装包/卸载/
// 撤权时才写), 全量替换避免"先删后加"中间出现的查不到窗口
//
// Registry 同时持有一份不可变的 Catalog: Intersect 方法把它闭合进裁决,
// 使得单个 *Registry 实例既能满足 pkgregistry.PermissionArbiter (安装时
// 裁决) 也能满足运行期查询 (Allowed), 不必拆成两个各管一半状态的类型
//
// 零值不可用, 必须经 NewRegistry 构造
type Registry struct {
	definitions *catalog.Registry
	snap        atomic.Pointer[snapshot]
	// stateMu serializes install-set publication with runtime grant writes. A
	// SetRuntimeState that loses the race with uninstall must observe the removed
	// package and fail instead of recreating persisted authority after cleanup.
	stateMu sync.Mutex
	// grants 是 GrantUser (危险) 权限的运行期授予状态. install-set (snap) 回答
	// 安装时授予了什么, grants 回答用户运行期确认/撤销了什么, Allowed 两者都看
	grants *grantStore

	revokerMu sync.RWMutex
	revoker   PermissionRevoker

	installRevokerMu sync.RWMutex
	installRevoker   InstallGrantRevoker

	projectorMu sync.RWMutex
	projector   RuntimePermissionProjector
}

type snapshot struct {
	byPackage map[string]map[string]struct{}
	// consentExempt 是"系统软件"集合, 见 Grant.ConsentExempt. 与 byPackage
	// 同一次 Replace 原子换入 —— 两者分开更新会出现一个窗口, 期间某个包已经
	// 拿到新权限却还带着旧的豁免判定
	consentExempt map[string]struct{}
}

// NewRegistry binds runtime grants to the one central definition catalog.
func NewRegistry(definitions *catalog.Registry) *Registry {
	r := &Registry{definitions: definitions, grants: newGrantStore()}
	r.snap.Store(&snapshot{
		byPackage:     map[string]map[string]struct{}{},
		consentExempt: map[string]struct{}{},
	})
	return r
}

// NewDefaultRegistry is primarily useful in tests and standalone tools. The
// production assembly constructs one catalog.Registry and shares it explicitly.
func NewDefaultRegistry() *Registry {
	definitions, err := catalog.NewDefaultRegistry()
	if err != nil {
		panic(fmt.Sprintf("permission: invalid default catalog: %v", err))
	}
	return NewRegistry(definitions)
}

// SetGrantStore 接线运行期授予状态的持久化目录与撤销联动.
// 装配期由 main.go 调用; stateDir 为 /var/lib/nervus/registry, revoker 由 control 实现
//
//	(撤销 motion 组权限时递增 motion epoch). 调用后从磁盘载入已有状态
func (r *Registry) SetGrantStore(stateDir string, revoker LeaseRevoker, aud audit.Recorder) {
	r.grants.mu.Lock()
	r.grants.stateDir = stateDir
	r.grants.revoker = revoker
	r.grants.aud = aud
	r.grants.mu.Unlock()
	r.grants.load()
}

// PermissionRevoker invalidates data-plane state authorized by one permission.
// IPC owns this hook so it can close route tokens before scanning transfers.
type PermissionRevoker interface {
	RevokePermission(packageID, permission string)
}

// InstallGrantRevoker removes authority already projected into a running
// process when Replace drops an install-time grant. Implementations must not
// perform package lookups, systemd I/O, or waits: Replace may be called while
// pkgregistry holds its transaction mutex.
type InstallGrantRevoker interface {
	RevokeInstallGrant(packageID, permission string)
}

// RuntimePermissionProjector applies a USER_CONSENT decision to authority
// outside the IPC data plane, such as writable paths in an already-running
// process sandbox. It is invoked only by SetRuntimeState, never by Replace:
// package projection may execute while pkgregistry holds its transaction lock.
type RuntimePermissionProjector interface {
	ProjectRuntimePermission(packageID, permission string, allowed bool) error
}

// SetPermissionRevoker installs the runtime revocation hook.
func (r *Registry) SetPermissionRevoker(revoker PermissionRevoker) {
	if r == nil {
		return
	}
	r.revokerMu.Lock()
	r.revoker = revoker
	r.revokerMu.Unlock()
}

// SetInstallGrantRevoker installs the non-blocking process-authority hook used
// by Replace after the data-plane revoker has run.
func (r *Registry) SetInstallGrantRevoker(revoker InstallGrantRevoker) {
	if r == nil {
		return
	}
	r.installRevokerMu.Lock()
	r.installRevoker = revoker
	r.installRevokerMu.Unlock()
}

// SetRuntimePermissionProjector installs the runtime sandbox projection hook.
func (r *Registry) SetRuntimePermissionProjector(projector RuntimePermissionProjector) {
	if r == nil {
		return
	}
	r.projectorMu.Lock()
	r.projector = projector
	r.projectorMu.Unlock()
}

// Intersect 用 Registry 自带的 Catalog 裁决一次安装请求 (见 intersect.go)
//
// 满足 pkgregistry.PermissionArbiter: 安装流程只知道"请求权限 + trust",
// Catalog 是 permission 内部状态, 不需要也不应该由调用方传入
//
// 对未初始化的 Registry fail-safe: 零值 Catalog 视为"没有任何已注册权限",
// 全部请求都会被拒绝, 而不是 panic
func (r *Registry) IntersectAt(
	definitions *catalog.Snapshot,
	requested []string,
	source catalog.SourceKind,
	trust identity.TrustProfile,
	signers catalog.SignerEvidence,
) (granted, denied []string) {
	if r == nil || definitions == nil {
		return nil, append([]string(nil), requested...)
	}
	for _, permissionID := range requested {
		definition, ok := definitions.Permission(permissionID)
		if !ok || trust < definition.MinimumTrust {
			denied = append(denied, permissionID)
			continue
		}
		if definition.RequiredSignerRole != "" && !signers.HasRole(definition.RequiredSignerRole) {
			denied = append(denied, permissionID)
			continue
		}
		switch definition.GrantMode {
		case ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT:
			// USER_CONSENT enters the install set here; AllowedAt additionally
			// requires the system-owned runtime grant state.
		case ipcv1.GrantMode_GRANT_MODE_SIGNATURE:
			if !signers.SameIdentity(definition.Owner.Signers) {
				denied = append(denied, permissionID)
				continue
			}
		case ipcv1.GrantMode_GRANT_MODE_PRIVILEGED:
			if source != catalog.SourceKindSystemImage ||
				(trust != identity.TrustOEM && trust != identity.TrustPlatform) {
				denied = append(denied, permissionID)
				continue
			}
		case ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY:
			if source != catalog.SourceKindSystemImage || trust != identity.TrustPlatform {
				denied = append(denied, permissionID)
				continue
			}
		default:
			denied = append(denied, permissionID)
			continue
		}
		granted = append(granted, permissionID)
	}
	return granted, denied
}

// Replace 原子替换整份已授予权限索引
//
// 由 pkgregistry 在启动扫描与每次 Install 提交后全量推送 (与 identity 接收
// pkgregistry 投影的方式一致, 见 pkgregistry/module.go 的 projectIdentity).
// 全量替换而不是增量改, 理由与 identity.Registry.Replace 相同: 增量接口会
// 诱使调用方"先删后加", 中间存在一个查不到的窗口
//
// 校验失败时整份拒绝, 旧快照原样保留: 宁可继续用上一份已知良好的授权状态,
// 也不要装载一份自相矛盾的
func (r *Registry) Replace(grants []Grant) error {
	next := make(map[string]map[string]struct{}, len(grants))
	exempt := make(map[string]struct{})
	for _, g := range grants {
		if g.PackageID == "" {
			return fmt.Errorf("permission: grant has empty package id")
		}
		if _, dup := next[g.PackageID]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicatePackageID, g.PackageID)
		}
		perms := make(map[string]struct{}, len(g.Permissions))
		for _, p := range g.Permissions {
			perms[p] = struct{}{}
		}
		next[g.PackageID] = perms
		if g.ConsentExempt {
			exempt[g.PackageID] = struct{}{}
		}
	}
	r.stateMu.Lock()
	previous := r.snap.Swap(&snapshot{byPackage: next, consentExempt: exempt})
	r.stateMu.Unlock()
	if previous != nil {
		for packageID, oldPermissions := range previous.byPackage {
			newPermissions := next[packageID]
			for permissionID := range oldPermissions {
				if _, retained := newPermissions[permissionID]; !retained {
					// Route/Transfer authority closes before any process sandbox
					// teardown is requested.
					r.revokePermission(packageID, permissionID)
					r.revokeInstallGrant(packageID, permissionID)
				}
			}
		}
	}
	return nil
}

// Allowed 报告 packageID 是否已被授予 permission
//
// 对未初始化的 Registry (未经 NewRegistry 的 &Registry{}, 甚至 typed-nil)
// 同样 fail-safe 返回 false (拒绝) 而不是 panic - 这里的 fail-safe 方向必须
// 格外小心: identity.Lookup 对未初始化状态返回"查无此人"是安全的默认拒绝,
// Allowed 返回 false 同样是默认拒绝, 两者方向一致, 不存在"未初始化时反而
// 放行"的风险
//
// 要求"每次调用时仍做快速权限与存活复核, 以支持动态撤权": 本方法
// 每次都读最新快照, 不缓存在调用方 - 写时复制 + 原子指针天然让 Replace 后
// 的下一次 Allowed 立刻看到新状态
func (r *Registry) Allowed(packageID, permission string) bool {
	if r == nil || r.definitions == nil {
		return false
	}
	return r.AllowedAt(r.definitions.Current(), packageID, permission)
}

// AllowedAt performs the grant and definition checks against one caller-owned
// immutable Snapshot, so an endpoint Route cannot mix catalog revisions.
func (r *Registry) AllowedAt(
	definitions *catalog.Snapshot,
	packageID string,
	permission string,
) bool {
	if r == nil || definitions == nil {
		return false
	}
	definition, defined := definitions.Permission(permission)
	if !defined {
		return false
	}
	snap := r.snap.Load()
	if snap == nil {
		return false
	}
	perms, ok := snap.byPackage[packageID]
	if !ok {
		return false
	}
	if _, ok = perms[permission]; !ok {
		return false // 安装期就没授予 (或已被卸载/降权投影出去)
	}
	// USER_CONSENT permissions: the install set only proves eligibility; actual
	// access requires the system-owned runtime grant state.
	// == Granted (两者都通过才放行)
	if definition.GrantMode == ipcv1.GrantMode_GRANT_MODE_USER_CONSENT {
		// 系统软件除外: 它与内核同批发布, 同一条签名链, 用户装机时就已经接受
		// 了它们. 再问一遍不增加安全性 —— 用户唯一能做的选择是"同意", 否则
		// 文件管理器打不开文件. 判据见 Grant.ConsentExempt
		if _, exempt := snap.consentExempt[packageID]; exempt {
			return true
		}
		return r.grants.state(packageID, permission) == GrantStateGranted
	}
	return true
}

// SetRuntimeState 设置一个 GrantUser 权限的运行期授予状态并持久化. 只有 GrantUser 权限有运行期状态, 对其它 Mode 调用返回错误. 撤销
// motion 组权限会联动 control 撤租 + 递增 motion epoch
//
// 目前唯一入口是 admin socket (nervusctl), 由 socket 自身的 peer 凭据把关.
// 尚不存在面向应用的 IPC 授予接口: 那需要先定「谁显示授权弹窗」, 该组件必须是
// platform-release 签名的独立系统服务, 不能是设置应用
func (r *Registry) SetRuntimeState(packageID, permission string, state GrantState) error {
	if r == nil {
		return fmt.Errorf("permission: nil registry")
	}
	if !state.valid() {
		return fmt.Errorf("permission: invalid grant state %d", state)
	}
	if r.definitions == nil {
		return fmt.Errorf("permission: definition catalog unavailable")
	}
	entry, ok := r.definitions.Current().Permission(permission)
	if !ok {
		return fmt.Errorf("permission: unknown permission %q", permission)
	}
	if entry.GrantMode != ipcv1.GrantMode_GRANT_MODE_USER_CONSENT {
		return fmt.Errorf("permission: %q is not a user-grantable (dangerous) permission", permission)
	}
	r.stateMu.Lock()
	snap := r.snap.Load()
	installed := false
	if snap != nil {
		if permissions := snap.byPackage[packageID]; permissions != nil {
			_, installed = permissions[permission]
		}
	}
	if !installed {
		r.stateMu.Unlock()
		return fmt.Errorf(
			"permission: package %q has no installed grant for %q",
			packageID, permission,
		)
	}
	if err := r.grants.set(
		packageID,
		permission,
		state,
		entry.RiskClass == ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
	); err != nil {
		r.stateMu.Unlock()
		return err
	}
	r.stateMu.Unlock()
	if state != GrantStateGranted {
		// Close route tokens and transfers before rebuilding process sandboxes.
		// From this point no new IPC work can be authorized by the old grant.
		r.revokePermission(packageID, permission)
	}
	if err := r.projectRuntimePermission(packageID, permission); err != nil {
		// The persisted decision remains authoritative and is deliberately not
		// rolled back: restoring a grant because process teardown failed would
		// reopen IPC authority while the caller believes it revoked access.
		return fmt.Errorf("permission: project runtime state for %q/%q: %w", packageID, permission, err)
	}
	return nil
}

// GrantStateOf 返回一个权限当前的运行期授予状态 (供权限 UI 展示/诊断)
func (r *Registry) GrantStateOf(packageID, permission string) GrantState {
	if r == nil {
		return GrantStateNotRequested
	}
	return r.grants.state(packageID, permission)
}

// ClearPackage 删除某 Package 的全部运行期授予状态, 供卸载路径调用. 安装期
// 集合 (snap) 由 pkgregistry 的 Replace 投影负责剔除, 这里只清运行期 _grants.json,
// 否则同 ID 重装会继承旧的危险权限授予
func (r *Registry) ClearPackage(packageID string) error {
	if r == nil {
		return nil
	}
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	return r.grants.clearPackage(packageID)
}

// Len 返回当前持有已授予权限记录的 Package 数, 供诊断与测试使用
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	snap := r.snap.Load()
	if snap == nil {
		return 0
	}
	return len(snap.byPackage)
}

func (r *Registry) revokePermission(packageID, permissionID string) {
	r.revokerMu.RLock()
	revoker := r.revoker
	r.revokerMu.RUnlock()
	if revoker != nil {
		revoker.RevokePermission(packageID, permissionID)
	}
}

func (r *Registry) revokeInstallGrant(packageID, permissionID string) {
	r.installRevokerMu.RLock()
	revoker := r.installRevoker
	r.installRevokerMu.RUnlock()
	if revoker != nil {
		revoker.RevokeInstallGrant(packageID, permissionID)
	}
}

func (r *Registry) projectRuntimePermission(packageID, permissionID string) error {
	r.projectorMu.RLock()
	projector := r.projector
	r.projectorMu.RUnlock()
	if projector == nil {
		return nil
	}
	return projector.ProjectRuntimePermission(
		packageID,
		permissionID,
		r.Allowed(packageID, permissionID),
	)
}
