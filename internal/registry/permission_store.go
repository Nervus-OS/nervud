package registry

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"nervud/internal/config"
)

// PermissionStore is the permission registry.
// Builtin permissions are defined in code and rebuilt on every start; the file only
// carries their allow lists. Custom permissions declared by services are stored whole.
// 权限注册表：内置权限定义在代码里，每次启动重新装入，文件只保存它们的 allow 列表；
// 服务声明的自定义权限整条保存在文件里
type PermissionStore struct {
	mu          sync.RWMutex
	permissions map[string]*Permission // ID -> Permission
}

func NewPermissionStore() *PermissionStore {
	return &PermissionStore{
		permissions: make(map[string]*Permission),
	}
}

// Load builds the registry from the builtin table and the registry file
// 先装入代码中的内置权限，再合并文件中的自定义权限
func (s *PermissionStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	perms, err := loadBuiltinPermissions()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(config.Get().PermissionRegistryPath)
	if os.IsNotExist(err) {
		s.permissions = perms
		return nil
	}
	if err != nil {
		return fmt.Errorf("read permission registry file: %w", err)
	}

	var stored []*Permission
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("unmarshal permission registry: %w", err)
	}

	for _, p := range stored {
		existing, exists := perms[p.ID]
		if p.IsBuiltin() {
			// Builtin definitions come from code; the file only carries the allow list.
			// An entry whose definition is gone is stale and dropped.
			// 内置权限的定义以代码为准，文件只带回 allow 列表；
			// 代码中已不存在的条目直接丢弃
			if !exists {
				slog.Warn("drop unknown builtin permission", "id", p.ID)
				continue
			}
			existing.AllowedPackages = slices.Clone(p.AllowedPackages)
			continue
		}

		if err := validatePermission(p); err != nil {
			return fmt.Errorf("load permission registry: %w", err)
		}
		if exists {
			return fmt.Errorf("load permission registry: %w: %s (declared by %s and %s)",
				ErrPermissionConflict, p.ID, existing.Source, p.Source)
		}
		perms[p.ID] = p
	}

	s.permissions = perms
	return nil
}

// loadBuiltinPermissions validates the builtin table and returns it as a map
func loadBuiltinPermissions() (map[string]*Permission, error) {
	perms := make(map[string]*Permission, len(builtinPermissions))
	for i := range builtinPermissions {
		p := builtinPermissions[i]
		if err := validatePermission(&p); err != nil {
			return nil, fmt.Errorf("builtin permission table: %w", err)
		}
		if _, exists := perms[p.ID]; exists {
			return nil, fmt.Errorf("builtin permission table: duplicate id %s", p.ID)
		}
		perms[p.ID] = &p
	}
	return perms, nil
}

// commit writes the next state to disk first, then swaps it into memory,
// so memory and disk stay consistent when write fails
// 先写盘再替换内存，写盘失败时内存保持原状
func (s *PermissionStore) commit(next map[string]*Permission) error {
	if err := s.save(next); err != nil {
		return err
	}
	s.permissions = next
	return nil
}

// save writes every permission to file, sorted by ID
// 全部权限都写入文件，按 ID 排序便于比对
func (s *PermissionStore) save(perms map[string]*Permission) error {
	list := make([]*Permission, 0, len(perms))
	for _, p := range perms {
		list = append(list, p.clone())
	}
	slices.SortFunc(list, func(a, b *Permission) int {
		return strings.Compare(a.ID, b.ID)
	})

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal permission registry: %w", err)
	}

	return writeFileAtomic(config.Get().PermissionRegistryPath, data)
}

// writeFileAtomic writes data to a temporary file and renames it over path
// 先写临时文件，再整体替换目标文件
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}

	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpFile, path); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// Get returns a copy of the permission with the given ID
// 返回具有给定 ID 的权限的副本
func (s *PermissionStore) Get(id string) (Permission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.permissions[id]
	if !exists {
		return Permission{}, false
	}
	return *p.clone(), true
}

// Has reports whether the permission exists
// 判断权限是否存在
func (s *PermissionStore) Has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.permissions[id]
	return exists
}

// List returns copies of all permissions, sorted by ID
// 返回所有权限的副本，按 ID 排序
func (s *PermissionStore) List() []Permission {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]Permission, 0, len(s.permissions))
	for _, p := range s.permissions {
		list = append(list, *p.clone())
	}
	slices.SortFunc(list, func(a, b Permission) int {
		return strings.Compare(a.ID, b.ID)
	})
	return list
}

// IsAllowed reports whether a package may use a permission. It ignores whether any
// component actually requested it; that is checked by the Registry.
// 询问某个包是否被准许某项权限；是否申请过由 Registry 再查
func (s *PermissionStore) IsAllowed(pkgID string, role ComponentRole, permID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.permissions[permID]
	if !exists {
		return false
	}
	if p.IsSystem() && role != RolePlatform {
		return false
	}
	if role == RolePlatform {
		// Platform packages never need user confirmation
		// platform 角色的包一律免确认
		return true
	}
	if !p.NeedUserConfirm {
		return true
	}
	return containsString(p.AllowedPackages, pkgID)
}

// Allow records that a package holds a permission after user confirmation
// 记录一个包经用户确认后获得某项权限
func (s *PermissionStore) Allow(permID, pkgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.permissions[permID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrPermissionNotFound, permID)
	}
	if containsString(p.AllowedPackages, pkgID) {
		return nil
	}

	next := maps.Clone(s.permissions)
	cp := p.clone()
	cp.AllowedPackages = append(cp.AllowedPackages, pkgID)
	slices.Sort(cp.AllowedPackages)
	next[permID] = cp

	return s.commit(next)
}

// Revoke removes a package's hold on a permission
// 撤销某个包对某项权限的授权
func (s *PermissionStore) Revoke(permID, pkgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.permissions[permID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrPermissionNotFound, permID)
	}
	if !containsString(p.AllowedPackages, pkgID) {
		return nil
	}

	next := maps.Clone(s.permissions)
	cp := p.clone()
	cp.AllowedPackages = removeString(cp.AllowedPackages, pkgID)
	next[permID] = cp

	return s.commit(next)
}

// applyPackage registers the custom permissions declared by a package and checks
// that every permission it requests exists. Grants the package no longer requests
// are dropped. It returns the previous state so the caller can roll back.
// 登记包内服务声明的自定义权限，并检查它申请的权限都存在；不再申请的权限授权会被清除。
// 返回改动前的状态供调用方回滚
func (s *PermissionStore) applyPackage(pkg Package) (map[string]*Permission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := maps.Clone(s.permissions)

	// Replace every permission previously declared by this package
	// 整体替换这个包之前声明的全部权限
	for id, p := range next {
		if !p.IsBuiltin() && PackageOf(p.Source) == pkg.ID {
			delete(next, id)
		}
	}

	for _, comp := range pkg.Components {
		for _, add := range comp.PermissionAdditions {
			p := newCustomPermission(comp.ID, add)
			if err := validatePermission(p); err != nil {
				return nil, err
			}
			if existing, exists := next[p.ID]; exists {
				return nil, fmt.Errorf("%w: %s is declared by %s", ErrPermissionConflict, p.ID, existing.Source)
			}
			next[p.ID] = p
		}
	}

	requested := pkg.requestedPermissions()
	for id := range requested {
		if _, exists := next[id]; !exists {
			return nil, fmt.Errorf("%w: %s", ErrPermissionNotFound, id)
		}
	}

	// A package that stopped requesting a permission loses its grant
	// 不再申请的权限，包在 allow 列表里的记录要清掉
	for id, p := range next {
		if _, stillRequested := requested[id]; stillRequested {
			continue
		}
		if !containsString(p.AllowedPackages, pkg.ID) {
			continue
		}
		cp := p.clone()
		cp.AllowedPackages = removeString(cp.AllowedPackages, pkg.ID)
		next[id] = cp
	}

	previous := s.permissions
	if err := s.commit(next); err != nil {
		return nil, err
	}
	return previous, nil
}

// removePackage drops every permission declared by a package and removes the package
// from every allow list. It returns the previous state so the caller can roll back.
// 删除某个包声明的全部权限，并把这个包从所有 allow 列表中移除；
// 返回改动前的状态供调用方回滚
func (s *PermissionStore) removePackage(pkgID string) (map[string]*Permission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := maps.Clone(s.permissions)

	for id, p := range next {
		if !p.IsBuiltin() && PackageOf(p.Source) == pkgID {
			delete(next, id)
			continue
		}
		if containsString(p.AllowedPackages, pkgID) {
			cp := p.clone()
			cp.AllowedPackages = removeString(cp.AllowedPackages, pkgID)
			next[id] = cp
		}
	}

	previous := s.permissions
	if err := s.commit(next); err != nil {
		return nil, err
	}
	return previous, nil
}

// restore puts a previous state back after the component side of an operation failed
// 组件表一侧失败时，把权限表恢复到改动前的状态
func (s *PermissionStore) restore(previous map[string]*Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.commit(previous)
}

// groupIDs returns the permission groups a component joins at launch: the
// group-controlled permissions it requested that its package is allowed to use
// 返回组件启动时要加入的附属组：它申请过、且所属包已获准的组控制型权限
func (s *PermissionStore) groupIDs(pkgID string, role ComponentRole, requested []string) []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var gids []uint32
	for _, id := range requested {
		p, exists := s.permissions[id]
		if !exists || !s.isAllowedLocked(p, pkgID, role) || !p.IsGroupControlled() {
			continue
		}
		gids = append(gids, uint32(p.GID))
	}
	slices.Sort(gids)
	return slices.Compact(gids)
}

// isAllowedLocked is IsAllowed for callers already holding the lock
// 供已持有锁的调用方使用的 IsAllowed
func (s *PermissionStore) isAllowedLocked(p *Permission, pkgID string, role ComponentRole) bool {
	if p.IsSystem() && role != RolePlatform {
		return false
	}
	if role == RolePlatform || !p.NeedUserConfirm {
		return true
	}
	return containsString(p.AllowedPackages, pkgID)
}
