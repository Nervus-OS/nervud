package registry

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"os/user"
	"slices"
	"strings"
	"sync"

	"nervud/internal/config"
)

// PackageStore holds the installed packages and the indexes derived from them.
// Packages are the primary data; components and UIDs only exist as indexes.
// 包表：包是主数据，组件表和 UID 表只是由包推导出来的索引
type PackageStore struct {
	mu         sync.RWMutex
	packages   map[string]*Package   // package ID -> Package
	components map[string]*Component // component ID -> Component
	uidIndex   map[int32]*Component  // UID -> Component
}

func NewPackageStore() *PackageStore {
	return &PackageStore{
		packages:   make(map[string]*Package),
		components: make(map[string]*Component),
		uidIndex:   make(map[int32]*Component),
	}
}

// Load reads the registry file and rebuilds every index
// 读取注册文件并重建全部索引
func (s *PackageStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(config.Get().ComponentRegistryPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read registry file: %w", err)
	}

	var packages []*Package
	if err := json.Unmarshal(data, &packages); err != nil {
		return fmt.Errorf("unmarshal registry: %w", err)
	}

	byID := make(map[string]*Package, len(packages))
	components := make(map[string]*Component)
	uidIndex := make(map[int32]*Component)

	for _, pkg := range packages {
		if err := pkg.validate(); err != nil {
			return fmt.Errorf("load registry: %w", err)
		}
		if _, dup := byID[pkg.ID]; dup {
			return fmt.Errorf("load registry: duplicate package %s", pkg.ID)
		}
		byID[pkg.ID] = pkg

		for _, comp := range pkg.Components {
			if err := checkComponentIdentity(comp); err != nil {
				return fmt.Errorf("load registry: %w", err)
			}
			if existing, dup := uidIndex[comp.UID]; dup {
				return fmt.Errorf("load registry: uid %d used by both %s and %s",
					comp.UID, existing.ID, comp.ID)
			}
			components[comp.ID] = comp
			uidIndex[comp.UID] = comp
		}
	}

	s.packages = byID
	s.components = components
	s.uidIndex = uidIndex
	return nil
}

// save writes the packages to disk, sorted by package ID and component ID
// 按包 ID 和组件 ID 排序后写盘
func (s *PackageStore) save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.persist(s.packages)
}

// persist writes a package map without touching the store lock state,
// so callers already holding the lock can reuse it
// 写入一份包映射；调用方已持有锁时直接复用
func (s *PackageStore) persist(packages map[string]*Package) error {
	sorted := make([]*Package, 0, len(packages))
	for _, pkg := range packages {
		cp := clonePackage(pkg)
		slices.SortFunc(cp.Components, func(a, b *Component) int {
			return strings.Compare(a.ID, b.ID)
		})
		sorted = append(sorted, &cp)
	}
	slices.SortFunc(sorted, func(a, b *Package) int {
		return strings.Compare(a.ID, b.ID)
	})

	data, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal registry: %w", err)
	}

	return writeFileAtomic(config.Get().ComponentRegistryPath, data)
}

// GetPackage returns a copy of the package with the given ID
// 返回具有给定 ID 的包的副本
func (s *PackageStore) GetPackage(id string) (Package, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pkg, exists := s.packages[id]
	if !exists {
		return Package{}, false
	}
	return clonePackage(pkg), true
}

// ListPackages returns copies of all packages, sorted by ID
func (s *PackageStore) ListPackages() []Package {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]Package, 0, len(s.packages))
	for _, pkg := range s.packages {
		list = append(list, clonePackage(pkg))
	}
	slices.SortFunc(list, func(a, b Package) int {
		return strings.Compare(a.ID, b.ID)
	})
	return list
}

// GetComponent returns a copy of the component with the given ID
// 返回具有给定 ID 的组件的副本
func (s *PackageStore) GetComponent(id string) (Component, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	comp, exists := s.components[id]
	if !exists {
		return Component{}, false
	}
	return cloneComponent(comp), true
}

// GetComponentByUID returns a copy of the component with the given UID
// 返回具有给定 UID 的组件的副本
func (s *PackageStore) GetComponentByUID(uid int32) (Component, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	comp, exists := s.uidIndex[uid]
	if !exists {
		return Component{}, false
	}
	return cloneComponent(comp), true
}

// ListComponents returns copies of all components, sorted by ID
func (s *PackageStore) ListComponents() []Component {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]Component, 0, len(s.components))
	for _, comp := range s.components {
		list = append(list, cloneComponent(comp))
	}
	slices.SortFunc(list, func(a, b Component) int {
		return strings.Compare(a.ID, b.ID)
	})
	return list
}

// HasComponent reports whether a component ID is already taken
// 判断组件 ID 是否已被占用
func (s *PackageStore) HasComponent(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.components[id]
	return exists
}

// ComponentsInPackage returns copies of every component in a package
// 返回某个包内的全部组件
func (s *PackageStore) ComponentsInPackage(packageID string) []Component {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pkg, exists := s.packages[packageID]
	if !exists {
		return nil
	}

	list := make([]Component, 0, len(pkg.Components))
	for _, comp := range pkg.Components {
		list = append(list, cloneComponent(comp))
	}
	return list
}

// putPackage writes a package as a whole. It backs both install and upgrade:
// components whose ID already exists keep their UID, new ones get a fresh one,
// and components that disappeared release theirs.
// 整包写入，安装和升级共用：ID 已存在的组件沿用原 UID，新组件分配新 UID，
// 新包不存在而旧版存在的组件释放 UID
func (s *PackageStore) putPackage(pkg Package) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextPackages := maps.Clone(s.packages)
	nextComponents := maps.Clone(s.components)
	nextUIDIndex := maps.Clone(s.uidIndex)

	// Drop the components of the previous version of this package
	// 先移除这个包上一版本的组件
	if old, exists := nextPackages[pkg.ID]; exists {
		for _, comp := range old.Components {
			delete(nextComponents, comp.ID)
			delete(nextUIDIndex, comp.UID)
		}
	}

	stored := &Package{
		ID:         pkg.ID,
		Role:       pkg.Role,
		Components: make([]*Component, 0, len(pkg.Components)),
	}

	for _, comp := range pkg.Components {
		cp := cloneComponent(comp)

		if existing, exists := s.components[cp.ID]; exists {
			// Keep the identity of an unchanged component, so files it owns keep working
			// 组件 ID 不变时沿用原身份，避免它遗留的文件失去归属
			cp.UID = existing.UID
			cp.GID = existing.GID
		} else {
			id, err := allocateID(nextUIDIndex)
			if err != nil {
				return err
			}
			cp.UID = id
			cp.GID = id
		}

		if err := checkComponentIdentity(&cp); err != nil {
			return err
		}

		stored.Components = append(stored.Components, &cp)
		nextComponents[cp.ID] = &cp
		nextUIDIndex[cp.UID] = &cp
	}
	nextPackages[pkg.ID] = stored

	if err := s.persist(nextPackages); err != nil {
		return err
	}

	s.packages = nextPackages
	s.components = nextComponents
	s.uidIndex = nextUIDIndex
	return nil
}

// removePackage removes a package together with its components
// 删除一个包及其全部组件
func (s *PackageStore) removePackage(packageID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pkg, exists := s.packages[packageID]
	if !exists {
		return fmt.Errorf("package not found: %s", packageID)
	}

	nextPackages := maps.Clone(s.packages)
	nextComponents := maps.Clone(s.components)
	nextUIDIndex := maps.Clone(s.uidIndex)

	for _, comp := range pkg.Components {
		delete(nextComponents, comp.ID)
		delete(nextUIDIndex, comp.UID)
	}
	delete(nextPackages, packageID)

	if err := s.persist(nextPackages); err != nil {
		return err
	}

	s.packages = nextPackages
	s.components = nextComponents
	s.uidIndex = nextUIDIndex
	return nil
}

// UpdateAvailability updates a component's availability status
// 更新组件当前是否可用的状态
func (s *PackageStore) UpdateAvailability(id string, available bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	comp, exists := s.components[id]
	if !exists {
		return fmt.Errorf("component not found: %s", id)
	}

	previous := comp.IsAvailable
	comp.IsAvailable = available

	if err := s.persist(s.packages); err != nil {
		comp.IsAvailable = previous
		return err
	}
	return nil
}

// allocateID picks a random free ID in the component range, ignoring the ones
// already used in the given index. A random pick avoids handing a freshly
// installed component the UID of a recently uninstalled one, which could let it
// inherit leftover files.
// 在组件区间内随机挑一个空闲 ID；随机分配可以避免新组件拿到刚被卸载组件的 UID，
// 从而继承它残留的文件
func allocateID(used map[int32]*Component) (int32, error) {
	cfg := config.Get()
	size := int(cfg.ComponentIDMax-cfg.ComponentIDMin) + 1
	if size <= 0 {
		return 0, fmt.Errorf("invalid component id range [%d, %d]", cfg.ComponentIDMin, cfg.ComponentIDMax)
	}

	reservedInRange := 0
	for id := range reservedGIDs {
		if id >= cfg.ComponentIDMin && id <= cfg.ComponentIDMax {
			reservedInRange++
		}
	}
	available := size - reservedInRange - len(used)
	if available <= 0 {
		return 0, fmt.Errorf("component id pool exhausted")
	}

	// Random attempts first; a nearly full range falls back to a linear scan
	// 先随机试探；区间快满时退化为顺序扫描
	const maxAttempts = 64
	for range maxAttempts {
		id := cfg.ComponentIDMin + rand.Int32N(int32(size))
		if idAvailable(id, used) {
			return id, nil
		}
	}
	for id := cfg.ComponentIDMin; id <= cfg.ComponentIDMax; id++ {
		if idAvailable(id, used) {
			return id, nil
		}
	}
	return 0, fmt.Errorf("component id pool exhausted")
}

// idAvailable reports whether a UID/GID can be given to a new component
// 判断一个 UID/GID 是否可以分配给新组件
func idAvailable(id int32, used map[int32]*Component) bool {
	if reservedGIDs[id] {
		return false
	}
	if _, taken := used[id]; taken {
		return false
	}
	// Skip IDs already owned by a base system user or group
	// 跳过基础系统已经占用的用户或组
	if _, err := user.LookupId(fmt.Sprint(id)); err == nil {
		return false
	}
	if _, err := user.LookupGroupId(fmt.Sprint(id)); err == nil {
		return false
	}
	return true
}

// checkComponentIdentity requires the UID to be in the component range and the GID to equal it,
// which keeps every component's UID and GID unique and away from system and permission groups
// UID 必须在组件区间内，且 GID 必须等于 UID；这样每个组件的 UID、GID 都是独立的，
// 也不会和系统组、权限组重叠
func checkComponentIdentity(comp *Component) error {
	cfg := config.Get()
	if comp.UID < cfg.ComponentIDMin || comp.UID > cfg.ComponentIDMax {
		return fmt.Errorf("component %s: uid %d out of range [%d, %d]",
			comp.ID, comp.UID, cfg.ComponentIDMin, cfg.ComponentIDMax)
	}
	if comp.GID != comp.UID {
		return fmt.Errorf("component %s: gid %d does not match uid %d", comp.ID, comp.GID, comp.UID)
	}
	return nil
}

// cloneComponent returns a copy that shares no slice with the original
// 返回不与原值共用切片的副本
func cloneComponent(comp *Component) Component {
	cp := *comp
	cp.RequestedPermissions = slices.Clone(comp.RequestedPermissions)
	cp.PermissionAdditions = slices.Clone(comp.PermissionAdditions)
	return cp
}

// clonePackage returns a copy with its own components
// 返回带有独立组件切片的包副本
func clonePackage(pkg *Package) Package {
	cp := Package{
		ID:         pkg.ID,
		Role:       pkg.Role,
		Components: make([]*Component, 0, len(pkg.Components)),
	}
	for _, comp := range pkg.Components {
		cc := cloneComponent(comp)
		cp.Components = append(cp.Components, &cc)
	}
	return cp
}
