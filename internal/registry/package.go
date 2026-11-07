package registry

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Package is the install unit. Its id is exactly three segments, and every
// component id starts with it followed by at least one more segment.
// 包是安装单位：包 ID 恰好三段，组件 ID 以包 ID 开头并至少再多一段
type Package struct {
	ID         string        `json:"id"`
	Role       ComponentRole `json:"role"` // developer or platform, shared by the whole package
	Components []*Component  `json:"components"`
}

// AddedPermission represents a custom permission declared by a service component
// 表示服务组件声明的自定义权限
type AddedPermission struct {
	ID string `json:"id"`
	// SystemPermission makes the permission available to platform packages only.
	// Other packages may still declare it in their requested permissions and install
	// successfully, but they never receive it.
	// 为 true 时只有 platform 角色的包能真正获得该权限；其他包可以申请、可以安装成功，
	// 但无法获得这个权限
	SystemPermission bool `json:"system_permission"`
	NeedUserConfirm  bool `json:"need_user_confirm"`
}

// PackageOf returns the package id of a component id, or the argument itself
// when it already has three segments.
// 返回组件 ID 所属的包 ID；参数本身是三段时原样返回
func PackageOf(id string) string {
	parts := strings.SplitN(id, ".", 4)
	if len(parts) < 4 {
		return id
	}
	return strings.Join(parts[:3], ".")
}

// SamePackage reports whether two component ids belong to the same package
// 判断两个组件是否属于同一个包
func SamePackage(a, b string) bool {
	return PackageOf(a) == PackageOf(b)
}

var idSegmentPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// validateSegments checks an id against a required number of segments
// 按要求的段数校验一个 ID
func validateSegments(id string, minSegments int) error {
	parts := strings.Split(id, ".")
	if len(parts) < minSegments {
		return fmt.Errorf("malformed id %q: need at least %d segments", id, minSegments)
	}
	for _, part := range parts {
		if !idSegmentPattern.MatchString(part) {
			return fmt.Errorf("malformed id %q: segment %q", id, part)
		}
	}
	return nil
}

// validatePackageID requires a package id with exactly three segments
// 包 ID 必须恰好三段
func validatePackageID(id string) error {
	if err := validateSegments(id, 3); err != nil {
		return err
	}
	if strings.Count(id, ".") != 2 {
		return fmt.Errorf("malformed package id %q: need exactly 3 segments", id)
	}
	if strings.HasPrefix(id, KernelReservedPrefix) {
		return fmt.Errorf("reserved package id: %s", id)
	}
	return nil
}

// validateComponentID requires a component id inside the package namespace with
// at least one segment of its own
// 组件 ID 必须在包命名空间内，并且至少比包 ID 多一段
func validateComponentID(pkgID, id string) error {
	if err := validateSegments(id, 4); err != nil {
		return err
	}
	if !strings.HasPrefix(id, pkgID+".") {
		return fmt.Errorf("component id %q is not inside package %q", id, pkgID)
	}
	if strings.HasPrefix(id, KernelReservedPrefix) {
		return fmt.Errorf("reserved component id: %s", id)
	}
	return nil
}

// validatePermissionIDForPackage requires a custom permission id inside the
// package namespace with at least one segment of its own
// 自定义权限 ID 必须在包命名空间内，并且至少比包 ID 多一段
func validatePermissionIDForPackage(pkgID, id string) error {
	if err := validateSegments(id, 4); err != nil {
		return err
	}
	if !strings.HasPrefix(id, pkgID+".") {
		return fmt.Errorf("permission id %q is not inside package %q", id, pkgID)
	}
	return nil
}

// validate checks the package and every component it contains
// 校验包及其全部组件
func (p *Package) validate() error {
	if err := validatePackageID(p.ID); err != nil {
		return err
	}
	if p.Role != RoleDeveloper && p.Role != RolePlatform {
		return fmt.Errorf("invalid role: %d", p.Role)
	}

	seenComponent := make(map[string]struct{}, len(p.Components))
	seenPermission := make(map[string]struct{})

	for _, comp := range p.Components {
		if err := validateComponentID(p.ID, comp.ID); err != nil {
			return err
		}
		if _, dup := seenComponent[comp.ID]; dup {
			return fmt.Errorf("duplicate component id: %s", comp.ID)
		}
		seenComponent[comp.ID] = struct{}{}

		if len(comp.PermissionAdditions) > 0 && comp.Type != ComponentTypeService {
			return fmt.Errorf("component %s: only services can declare permission_additions", comp.ID)
		}
		for _, add := range comp.PermissionAdditions {
			if err := validatePermissionIDForPackage(p.ID, add.ID); err != nil {
				return err
			}
			if _, dup := seenPermission[add.ID]; dup {
				return fmt.Errorf("%w: %s", ErrPermissionDuplicated, add.ID)
			}
			seenPermission[add.ID] = struct{}{}
		}

		comp.RequestedPermissions = dedupeStrings(comp.RequestedPermissions)
	}

	return nil
}

// requestedPermissions returns the union of the permissions requested by every
// component in the package
// 返回包内所有组件申请的权限 ID 集合
func (p *Package) requestedPermissions() map[string]struct{} {
	requested := make(map[string]struct{})
	for _, comp := range p.Components {
		for _, id := range comp.RequestedPermissions {
			requested[id] = struct{}{}
		}
	}
	return requested
}

// dedupeStrings removes duplicates while keeping the original order
// 去重并保持原有顺序
func dedupeStrings(list []string) []string {
	if len(list) == 0 {
		return list
	}
	seen := make(map[string]struct{}, len(list))
	out := make([]string, 0, len(list))
	for _, s := range list {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// containsString reports whether list contains s
// 判断切片是否包含某个字符串
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// removeString returns list without s, reusing the backing array only when it is
// owned by the caller; the result always has its own storage when something changed
// 返回去掉某个字符串的切片
func removeString(list []string, s string) []string {
	if !containsString(list, s) {
		return list
	}
	out := make([]string, 0, len(list)-1)
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// ErrInvalidPackage is returned when a package fails validation
var ErrInvalidPackage = errors.New("invalid package")
