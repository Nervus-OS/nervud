// 本文件是 permission 的权威运行期状态：Package ID -> 已授予权限集合，
// 供 ipc 的 Request 分派管线在裁决时查询
package permission

import (
	"fmt"
	"sync/atomic"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
)

// ErrDuplicatePackageID 一次 Replace 里两条 Grant 共用同一个 Package ID
var ErrDuplicatePackageID = fmt.Errorf("permission: duplicate package id in grant snapshot")

// Grant 是一个 Package 在某一时刻的全量已授予权限集合
//
// 这是 pkgregistry 推送给 permission 的投影单元，与 identity.Package 投影
// identity 所需字段的方式一致 - 只带 permission 用得着的两个字段
type Grant struct {
	PackageID   string
	Permissions []string
}

// Registry 是 permission 的权威运行期状态
//
// 照抄 identity.Registry / pkgregistry.Registry 的写时复制 + 原子指针 +
// 全量替换范式：读多写少（每次连接的每次 Request 都要查，只有装包/卸载/
// 撤权时才写），全量替换避免"先删后加"中间出现的查不到窗口
//
// Registry 同时持有一份不可变的 Catalog：Intersect 方法把它闭合进裁决，
// 使得单个 *Registry 实例既能满足 pkgregistry.PermissionArbiter（安装时
// 裁决）也能满足运行期查询（Allowed），不必拆成两个各管一半状态的类型
//
// 零值不可用，必须经 NewRegistry 构造
type Registry struct {
	catalog Catalog
	snap    atomic.Pointer[snapshot]
	// grants 是 GrantUser（危险）权限的运行期授予状态。install-set（snap）回答
	// 安装时授予了什么，grants 回答用户运行期确认/撤销了什么，Allowed 两者都看
	grants *grantStore
}

type snapshot struct {
	byPackage map[string]map[string]struct{}
}

// NewRegistry 用给定 Catalog 构造一个空的 Registry
func NewRegistry(cat Catalog) *Registry {
	r := &Registry{catalog: cat, grants: newGrantStore()}
	r.snap.Store(&snapshot{byPackage: map[string]map[string]struct{}{}})
	return r
}

// SetGrantStore 接线运行期授予状态的持久化目录与撤销联动。
// 装配期由 main.go 调用；stateDir 为 /var/lib/nervus/registry，revoker 由 control 实现
// （撤销 motion 组权限时递增 motion epoch）。调用后从磁盘载入已有状态
func (r *Registry) SetGrantStore(stateDir string, revoker LeaseRevoker, aud audit.Recorder) {
	r.grants.mu.Lock()
	r.grants.stateDir = stateDir
	r.grants.revoker = revoker
	r.grants.aud = aud
	r.grants.mu.Unlock()
	r.grants.load()
}

// Intersect 用 Registry 自带的 Catalog 裁决一次安装请求（见 intersect.go）
//
// 满足 pkgregistry.PermissionArbiter：安装流程只知道"请求权限 + trust"，
// Catalog 是 permission 内部状态，不需要也不应该由调用方传入
//
// 对未初始化的 Registry fail-safe：零值 Catalog 视为"没有任何已注册权限"，
// 全部请求都会被拒绝，而不是 panic
func (r *Registry) Intersect(requested []string, trust identity.TrustProfile, signerRoles []string) (granted, denied []string) {
	if r == nil {
		return nil, append([]string(nil), requested...)
	}
	return Intersect(requested, r.catalog, trust, signerRoles)
}

// Replace 原子替换整份已授予权限索引
//
// 由 pkgregistry 在启动扫描与每次 Install 提交后全量推送（与 identity 接收
// pkgregistry 投影的方式一致，见 pkgregistry/module.go 的 projectIdentity）。
// 全量替换而不是增量改，理由与 identity.Registry.Replace 相同：增量接口会
// 诱使调用方"先删后加"，中间存在一个查不到的窗口
//
// 校验失败时整份拒绝、旧快照原样保留：宁可继续用上一份已知良好的授权状态，
// 也不要装载一份自相矛盾的
func (r *Registry) Replace(grants []Grant) error {
	next := make(map[string]map[string]struct{}, len(grants))
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
	}
	r.snap.Store(&snapshot{byPackage: next})
	return nil
}

// Allowed 报告 packageID 是否已被授予 permission
//
// 对未初始化的 Registry（未经 NewRegistry 的 &Registry{}，甚至 typed-nil）
// 同样 fail-safe 返回 false（拒绝）而不是 panic - 这里的 fail-safe 方向必须
// 格外小心：identity.Lookup 对未初始化状态返回"查无此人"是安全的默认拒绝，
// Allowed 返回 false 同样是默认拒绝，两者方向一致，不存在"未初始化时反而
// 放行"的风险
//
// 要求"每次调用时仍做快速权限与存活复核，以支持动态撤权"：本方法
// 每次都读最新快照，不缓存在调用方 - 写时复制 + 原子指针天然让 Replace 后
// 的下一次 Allowed 立刻看到新状态
func (r *Registry) Allowed(packageID, permission string) bool {
	if r == nil {
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
		return false // 安装期就没授予（或已被卸载/降权投影出去）
	}
	// v1：不做运行期用户确认，install-set 命中即放行（见 V1GrantAll）。
	// 注意上面那条 install-set 检查【不】跳过：没在 manifest 里申请过的权限
	// 依然拿不到，v1 放宽的是「要不要确认」，不是「要不要声明」。
	if V1GrantAll {
		return true
	}
	// GrantUser（危险）权限：安装期集合只证明可请求，实际放行还要运行期状态
	// == Granted（两者都通过才放行）
	if entry, ok := r.catalog.Lookup(permission); ok && entry.Mode == GrantUser {
		return r.grants.state(packageID, permission) == GrantStateGranted
	}
	return true
}

// SetRuntimeState 设置一个 GrantUser 权限的运行期授予状态并持久化。只有 GrantUser 权限有运行期状态，对其它 Mode 调用返回错误。撤销
// motion 组权限会联动 control 撤租 + 递增 motion epoch
//
// 调用入口需 perm.permission.admin（全系统只有权限确认 UI 有） - 该执法在 IPC 请求
// 管线落地，本方法是被执法后的机制落点
func (r *Registry) SetRuntimeState(packageID, permission string, state GrantState) error {
	if r == nil {
		return fmt.Errorf("permission: nil registry")
	}
	if !state.valid() {
		return fmt.Errorf("permission: invalid grant state %d", state)
	}
	entry, ok := r.catalog.Lookup(permission)
	if !ok {
		return fmt.Errorf("permission: unknown permission %q", permission)
	}
	if entry.Mode != GrantUser {
		return fmt.Errorf("permission: %q is not a user-grantable (dangerous) permission", permission)
	}
	return r.grants.set(packageID, permission, state, entry.Group == GroupMotion)
}

// GrantStateOf 返回一个权限当前的运行期授予状态（供权限 UI 展示/诊断）
func (r *Registry) GrantStateOf(packageID, permission string) GrantState {
	if r == nil {
		return GrantStateNotRequested
	}
	return r.grants.state(packageID, permission)
}

// ClearPackage 删除某 Package 的全部运行期授予状态，供卸载路径调用。安装期
// 集合（snap）由 pkgregistry 的 Replace 投影负责剔除，这里只清运行期 _grants.json，
// 否则同 ID 重装会继承旧的危险权限授予
func (r *Registry) ClearPackage(packageID string) error {
	if r == nil {
		return nil
	}
	return r.grants.clearPackage(packageID)
}

// Len 返回当前持有已授予权限记录的 Package 数，供诊断与测试使用
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
