package registry

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"nervud/internal/kernel"
)

// Module owns the package and permission tables
// 注册模块持有包表和权限表
type Module struct {
	store     *PackageStore
	permStore *PermissionStore
	registry  *Registry
}

func (m *Module) Name() string {
	return "registry_package"
}

func (m *Module) Start(ctx context.Context) error {
	slog.Info("registry module starting")

	// Load the component registry
	// 加载包注册表
	m.store = NewPackageStore()
	if err := m.store.Load(); err != nil {
		slog.Error("failed to load package registry", "error", err)
		kernel.ReportFatal(ctx, err)
		return err
	}

	// Load the permission registry
	// 加载权限注册表
	m.permStore = NewPermissionStore()
	if err := m.permStore.Load(); err != nil {
		slog.Error("failed to load permission registry", "error", err)
		kernel.ReportFatal(ctx, err)
		return err
	}

	// Both tables must be ready before the registry is built
	// 两张表都加载完成后才能构造 Registry
	m.registry = NewRegistry(m.store, m.permStore)
	globalRegistry = m.registry

	slog.Info("registry loaded",
		"package_count", len(m.store.ListPackages()),
		"permission_count", len(m.permStore.List()))

	// Ensure permission groups exist and their paths carry the right ACLs
	// 确保权限组存在，且权限路径上的 ACL 正确。失败不致命：根文件系统可能只读
	if err := SetupPermissionGroups(); err != nil {
		slog.Error("setup permission groups failed", "error", err)
	}

	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	slog.Info("registry module stopping")
	return nil
}

// globalRegistry is the instance the package level functions below forward to
// 包级函数转发到的当前实例
var globalRegistry *Registry

// Current returns the current instance. Prefer the package level functions.
// 返回当前实例；优先使用包级函数
func Current() *Registry {
	return globalRegistry
}

// Registry combines the package and permission tables so that operations touching
// both are all or nothing. Lock order: Registry, then PackageStore or PermissionStore.
// 把包注册表和权限注册表合到一起，使同时修改两张表的操作要么全做要么全不做
type Registry struct {
	mu          sync.RWMutex
	packages    *PackageStore
	permissions *PermissionStore
}

func NewRegistry(packages *PackageStore, permissions *PermissionStore) *Registry {
	return &Registry{packages: packages, permissions: permissions}
}

// Packages returns the package table
func (r *Registry) Packages() *PackageStore {
	return r.packages
}

// Permissions returns the permission table
func (r *Registry) Permissions() *PermissionStore {
	return r.permissions
}

// InstallPackage writes a package together with the permissions it declares and
// requests. A requested permission the package's role cannot use, such as a system
// permission requested by a developer package, does not fail the install; permission
// checks simply report it as not held.
// 写入包以及它声明和申请的权限。
// 包的角色无法使用的权限不会导致安装失败，使用权限的时候会被当作没有持有该权限
func (r *Registry) InstallPackage(pkg Package) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := pkg.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPackage, err)
	}
	if err := r.validateInstallLocked(pkg); err != nil {
		return err
	}

	previous, err := r.permissions.applyPackage(pkg)
	if err != nil {
		return err
	}

	if err := r.packages.putPackage(pkg); err != nil {
		if rbErr := r.permissions.restore(previous); rbErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", err, rbErr)
		}
		return err
	}
	return nil
}

// validateInstallLocked checks permissions against the tables while the lock is held
// 在持锁状态下用两张表校验安装请求
func (r *Registry) validateInstallLocked(pkg Package) error {
	// Permissions this install would add may already be requested by the same package
	// 本次安装会新增的权限，同包组件可以申请
	declared := make(map[string]struct{})
	for _, comp := range pkg.Components {
		for _, add := range comp.PermissionAdditions {
			declared[add.ID] = struct{}{}
		}
	}

	for _, comp := range pkg.Components {
		for _, id := range comp.RequestedPermissions {
			if _, ok := declared[id]; ok {
				continue
			}
			if !r.permissions.Has(id) {
				return fmt.Errorf("%w: %s", ErrPermissionNotFound, id)
			}
		}
	}

	// A permission ID may not collide with an existing component ID, and a component
	// ID may not collide with an existing permission ID
	// 权限 ID 不能和已有组件 ID 相同，组件 ID 也不能和已有权限 ID 相同
	for _, comp := range pkg.Components {
		if r.permissions.Has(comp.ID) {
			return fmt.Errorf("%w: %s", ErrPermissionIDTaken, comp.ID)
		}
		for _, add := range comp.PermissionAdditions {
			if existing, ok := r.packages.GetComponent(add.ID); ok {
				return fmt.Errorf("%w: %s (component %s)", ErrPermissionIDTaken, add.ID, existing.ID)
			}
		}
	}
	return nil
}

// UninstallPackage removes a package, the permissions it declared, and every
// grant of those permissions held by other packages
// 注销包，同时删除它声明的权限以及其他包对这些权限的授权
func (r *Registry) UninstallPackage(pkgID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.packages.GetPackage(pkgID); !exists {
		return fmt.Errorf("package not found: %s", pkgID)
	}

	previous, err := r.permissions.removePackage(pkgID)
	if err != nil {
		return err
	}

	if err := r.packages.removePackage(pkgID); err != nil {
		if rbErr := r.permissions.restore(previous); rbErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", err, rbErr)
		}
		return err
	}
	return nil
}

// ConfirmPermission grants a permission to the package of a component after the user
// agreed. The package must request the permission through at least one component.
// 组件所属的包经用户同意后获得某项权限；包内至少要有一个组件申请过它
func (r *Registry) ConfirmPermission(componentID, permID string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pkgID, err := r.packageOfComponent(componentID)
	if err != nil {
		return err
	}
	if !r.packageRequests(pkgID, permID) {
		return fmt.Errorf("%w: %s", ErrPermissionNotRequested, permID)
	}
	return r.permissions.Allow(permID, pkgID)
}

// RevokePermission withdraws a package's hold on a permission
// 撤销组件所属的包对某项权限的授权
func (r *Registry) RevokePermission(componentID, permID string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pkgID, err := r.packageOfComponent(componentID)
	if err != nil {
		return err
	}
	return r.permissions.Revoke(permID, pkgID)
}

// HasPermission reports whether a component holds a permission: it must be declared
// at install and its package must be allowed to use it. Same-package access is not
// handled here; callers decide that themselves.
// 组件是否拥有某项权限：安装时必须声明过，且所属包获准使用。这里不处理同包放行
func (r *Registry) HasPermission(componentID, permID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	comp, exists := r.packages.GetComponent(componentID)
	if !exists || !containsString(comp.RequestedPermissions, permID) {
		return false
	}

	pkg, exists := r.packages.GetPackage(PackageOf(componentID))
	if !exists {
		return false
	}
	return r.permissions.IsAllowed(pkg.ID, pkg.Role, permID)
}

// CallerPermissions returns the permissions the caller requested, is allowed to use,
// and that the target component declared. It fills caller_permissions.
// 返回调用方申请过、已获准、且由目标组件声明的权限，用于填充 caller_permissions
func (r *Registry) CallerPermissions(callerID, targetID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	caller, exists := r.packages.GetComponent(callerID)
	if !exists {
		return nil
	}
	pkg, exists := r.packages.GetPackage(PackageOf(callerID))
	if !exists {
		return nil
	}

	var perms []string
	for _, id := range caller.RequestedPermissions {
		p, exists := r.permissions.Get(id)
		if !exists || p.Source != targetID {
			continue
		}
		if r.permissions.IsAllowed(pkg.ID, pkg.Role, id) {
			perms = append(perms, id)
		}
	}
	return perms
}

// LaunchGroups returns the supplementary groups a component process joins: every
// other component in the same package, the display group for apps, and the groups
// of its allowed group-controlled permissions
// 返回组件进程启动时加入的附属组：同包其他组件、App 的 display 组、
// 以及已获准的组控制型权限对应的组
func (r *Registry) LaunchGroups(componentID string) ([]uint32, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	comp, exists := r.packages.GetComponent(componentID)
	if !exists {
		return nil, fmt.Errorf("component not found: %s", componentID)
	}
	pkg, exists := r.packages.GetPackage(PackageOf(componentID))
	if !exists {
		return nil, fmt.Errorf("package not found: %s", PackageOf(componentID))
	}

	var groups []uint32
	for _, other := range pkg.Components {
		if other.ID == comp.ID {
			continue
		}
		// Never pull a broken identity into another component's group set
		// 不把身份异常的组件带进别人的附属组
		if err := checkComponentIdentity(other); err != nil {
			return nil, err
		}
		groups = append(groups, uint32(other.GID))
	}

	if comp.Type == ComponentTypeApp {
		groups = append(groups, uint32(GIDDisplay))
	}

	groups = append(groups, r.permissions.groupIDs(pkg.ID, pkg.Role, comp.RequestedPermissions)...)
	slices.Sort(groups)
	return slices.Compact(groups), nil
}

// LaunchCredential returns the identity to start a component with.
// Call it right before fork/exec; syscall.Access can be used to detect ids that'd
// disappeared from the system since registration.
// 启动组件前调用，返回 UID、主 GID 和附属组
func (r *Registry) LaunchCredential(componentID string) (LaunchCredential, error) {
	comp, exists := r.packages.GetComponent(componentID)
	if !exists {
		return LaunchCredential{}, fmt.Errorf("component not found: %s", componentID)
	}

	groups, err := r.LaunchGroups(componentID)
	if err != nil {
		return LaunchCredential{}, err
	}

	return LaunchCredential{
		UID:    uint32(comp.UID),
		GID:    uint32(comp.GID),
		Groups: groups,
	}, nil
}

// GetPackage returns a copy of the package with the given ID
func (r *Registry) GetPackage(id string) (Package, bool) {
	return r.packages.GetPackage(id)
}

// ListPackages returns copies of all packages
func (r *Registry) ListPackages() []Package {
	return r.packages.ListPackages()
}

// GetComponent returns a copy of the component with the given ID
func (r *Registry) GetComponent(id string) (Component, bool) {
	return r.packages.GetComponent(id)
}

// GetComponentByUID returns a copy of the component with the given UID
func (r *Registry) GetComponentByUID(uid int32) (Component, bool) {
	return r.packages.GetComponentByUID(uid)
}

// ListComponents returns copies of all components
func (r *Registry) ListComponents() []Component {
	return r.packages.ListComponents()
}

// packageOfComponent returns the package a component belongs to
// 返回组件所属的包 ID
func (r *Registry) packageOfComponent(componentID string) (string, error) {
	if _, exists := r.packages.GetComponent(componentID); !exists {
		return "", fmt.Errorf("component not found: %s", componentID)
	}
	return PackageOf(componentID), nil
}

// packageRequests reports whether any component in the package requests a permission
// 判断包内是否有组件申请过某项权限
func (r *Registry) packageRequests(pkgID, permID string) bool {
	for _, comp := range r.packages.ComponentsInPackage(pkgID) {
		if containsString(comp.RequestedPermissions, permID) {
			return true
		}
	}
	return false
}

// Package level wrappers around the current instance
// 包级包装函数，只负责找到当前实例

func InstallPackage(pkg Package) error {
	if globalRegistry == nil {
		return fmt.Errorf("registry not initialized")
	}
	return globalRegistry.InstallPackage(pkg)
}

func UninstallPackage(pkgID string) error {
	if globalRegistry == nil {
		return fmt.Errorf("registry not initialized")
	}
	return globalRegistry.UninstallPackage(pkgID)
}

func ConfirmPermission(componentID, permID string) error {
	if globalRegistry == nil {
		return fmt.Errorf("registry not initialized")
	}
	return globalRegistry.ConfirmPermission(componentID, permID)
}

func RevokePermission(componentID, permID string) error {
	if globalRegistry == nil {
		return fmt.Errorf("registry not initialized")
	}
	return globalRegistry.RevokePermission(componentID, permID)
}

func HasPermission(componentID, permID string) bool {
	if globalRegistry == nil {
		return false
	}
	return globalRegistry.HasPermission(componentID, permID)
}

func CallerPermissions(callerID, targetID string) []string {
	if globalRegistry == nil {
		return nil
	}
	return globalRegistry.CallerPermissions(callerID, targetID)
}

func GetPackage(id string) (Package, bool) {
	if globalRegistry == nil {
		return Package{}, false
	}
	return globalRegistry.GetPackage(id)
}

func ListPackages() []Package {
	if globalRegistry == nil {
		return nil
	}
	return globalRegistry.ListPackages()
}

func GetComponent(id string) (Component, bool) {
	if globalRegistry == nil {
		return Component{}, false
	}
	return globalRegistry.GetComponent(id)
}

func GetComponentByUID(uid int32) (Component, bool) {
	if globalRegistry == nil {
		return Component{}, false
	}
	return globalRegistry.GetComponentByUID(uid)
}

func ListComponents() []Component {
	if globalRegistry == nil {
		return nil
	}
	return globalRegistry.ListComponents()
}

// CredentialFor is the package level form of Registry.LaunchCredential; it is not
// called LaunchCredential because that name belongs to the returned type.
// Registry.LaunchCredential 的包级形式；因为名字被返回类型占用，故用此名
func CredentialFor(componentID string) (LaunchCredential, error) {
	if globalRegistry == nil {
		return LaunchCredential{}, fmt.Errorf("registry not initialized")
	}
	return globalRegistry.LaunchCredential(componentID)
}
