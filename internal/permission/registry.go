// 见 doc.go 的包说明
//
// 本文件是 permission 的权威运行期状态：Package ID -> 已授予权限集合，
// 供 ipc 的 Request 分派管线在裁决时查询（架构 §10.7）
package permission

import (
	"fmt"
	"sync/atomic"

	"github.com/nervus-os/nervud/internal/identity"
)

// ErrDuplicatePackageID 一次 Replace 里两条 Grant 共用同一个 Package ID
var ErrDuplicatePackageID = fmt.Errorf("permission: duplicate package id in grant snapshot")

// Grant 是一个 Package 在某一时刻的全量已授予权限集合
//
// 这是 pkgregistry 推送给 permission 的投影单元，与 identity.Package 投影
// identity 所需字段的方式一致——只带 permission 用得着的两个字段
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
}

type snapshot struct {
	byPackage map[string]map[string]struct{}
}

// NewRegistry 用给定 Catalog 构造一个空的 Registry
func NewRegistry(cat Catalog) *Registry {
	r := &Registry{catalog: cat}
	r.snap.Store(&snapshot{byPackage: map[string]map[string]struct{}{}})
	return r
}

// Intersect 用 Registry 自带的 Catalog 裁决一次安装请求（见 intersect.go）
//
// 满足 pkgregistry.PermissionArbiter：安装流程只知道"请求权限 + trust"，
// Catalog 是 permission 内部状态，不需要也不应该由调用方传入
//
// 对未初始化的 Registry fail-safe：零值 Catalog 视为"没有任何已注册权限"，
// 全部请求都会被拒绝，而不是 panic
func (r *Registry) Intersect(requested []string, trust identity.TrustProfile) (granted, denied []string) {
	if r == nil {
		return nil, append([]string(nil), requested...)
	}
	return Intersect(requested, r.catalog, trust)
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
// 同样 fail-safe 返回 false（拒绝）而不是 panic——这里的 fail-safe 方向必须
// 格外小心：identity.Lookup 对未初始化状态返回"查无此人"是安全的默认拒绝，
// Allowed 返回 false 同样是默认拒绝，两者方向一致，不存在"未初始化时反而
// 放行"的风险
//
// 架构 §10.7 要求"每次调用时仍做快速权限与存活复核，以支持动态撤权"：本方法
// 每次都读最新快照，不缓存在调用方——写时复制 + 原子指针天然让 Replace 后
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
	_, ok = perms[permission]
	return ok
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
