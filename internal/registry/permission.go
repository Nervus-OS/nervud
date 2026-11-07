package registry

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"nervud/internal/config"
)

// PermissionType represents the type of permission
// 权限类型：系统权限只能由系统组件申请，用户权限任何组件都可以申请
type PermissionType int

const (
	PermissionTypeSystem PermissionType = iota
	PermissionTypeUser
)

// String returns the string representation of PermissionType
func (t PermissionType) String() string {
	switch t {
	case PermissionTypeSystem:
		return "system"
	case PermissionTypeUser:
		return "user"
	default:
		return "unknown"
	}
}

const (
	// BuiltinPermissionSource is the source of all builtin permissions
	// 虚拟服务为所有内置权限的来源
	BuiltinPermissionSource = "nervud.system.server"

	// NoGID marks a permission that is not controlled by a user group.
	// GID 0 is a valid group (root), so a negative value is used instead.
	// 服务控制型权限不属于任何用户组；GID 0 是 root 组，因此用 -1 表示没有组
	NoGID int32 = -1

	// SystemPermissionPrefix and UserPermissionPrefix are reserved for builtin permissions
	// 内置权限 ID 的保留前缀，自定义权限不得使用
	SystemPermissionPrefix = "nervus.system.perm."
	UserPermissionPrefix   = "nervus.perm."

	// GIDRoot is the root group, used by nervus.system.perm.root
	GIDRoot int32 = 0
)

// reservedGIDs must never be allocated to a component (nobody / 16-bit -1)
// 分配组件 UID/GID 时需跳过的保留值
var reservedGIDs = map[int32]bool{65534: true, 65535: true}

// reservedPermissionPrefixes may only be used by builtin permissions.
// Append here to reserve another namespace.
// 保留前缀，勿用于自定义权限
var reservedPermissionPrefixes = []string{
	SystemPermissionPrefix,
	UserPermissionPrefix,
	KernelReservedPrefix,
}

var (
	ErrPermissionNotFound     = errors.New("permission not found")
	ErrPermissionConflict     = errors.New("permission already declared by another source")
	ErrPermissionDuplicated   = errors.New("permission declared twice in the same package")
	ErrPermissionNotRequested = errors.New("permission is not requested by any component in the package")
	ErrPermissionIDTaken      = errors.New("permission id collides with an existing component id")
)

// Permission represents an entry in the permission registry.
// Don't edit; Update by replacement.
// 权限注册表中的一条权限
type Permission struct {
	ID     string         `json:"id"`
	Type   PermissionType `json:"type"`
	Source string         `json:"source"` // declaring service component ID / 声明它的服务组件 ID

	GID int32 `json:"gid"` // GID of the permission

	NeedUserConfirm bool `json:"need_user_confirm"`

	// AllowedPackages lists the packages that hold this permission after user
	// confirmation. It only matters while NeedUserConfirm is set.
	// 需要用户确认时，已获准的包 ID
	AllowedPackages []string `json:"allowed_packages"`
}

// IsBuiltin reports whether the permission is predefined by the kernel
func (p *Permission) IsBuiltin() bool {
	return p.Source == BuiltinPermissionSource
}

// IsSystem reports whether the permission is a system permission
func (p *Permission) IsSystem() bool {
	return p.Type == PermissionTypeSystem
}

// IsGroupControlled reports whether access is controlled through a user group
// 是否为用户组控制型权限
func (p *Permission) IsGroupControlled() bool {
	return p.GID >= 0
}

// clone returns a copy that shares no slice with the original
// 返回不与原值共用切片的副本
func (p *Permission) clone() *Permission {
	cp := *p
	cp.AllowedPackages = slices.Clone(p.AllowedPackages)
	return &cp
}

// newCustomPermission converts a service-declared AddedPermission into a registry entry
// 将服务声明的自定义权限转换为权限注册表条目
func newCustomPermission(serviceID string, add AddedPermission) *Permission {
	permType := PermissionTypeUser
	if add.SystemPermission {
		permType = PermissionTypeSystem
	}

	return &Permission{
		ID:              add.ID,
		Type:            permType,
		Source:          serviceID,
		GID:             NoGID,
		NeedUserConfirm: add.NeedUserConfirm,
	}
}

// permissionRule validates one aspect of a permission entry.
// Append to permissionRules to add a new constraint.
// 单条校验规则；需要新增约束时，往 permissionRules 里追加即可
type permissionRule func(p *Permission) error

var permissionRules = []permissionRule{
	ruleValidID,
	ruleValidType,
	ruleSystemNoConfirm,
	ruleGIDNotInComponentRange,
	ruleBuiltinPrefix,
	ruleCustomNotReserved,
	ruleCustomNoGroup,
	ruleCustomNamespace,
}

var permissionIDPattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

// validatePermission runs every rule against the permission (the methods below all define rules)
// 检查权限是否符合约束 (下面的方法均为约束内容)
func validatePermission(p *Permission) error {
	for _, rule := range permissionRules {
		if err := rule(p); err != nil {
			return fmt.Errorf("invalid permission %q: %w", p.ID, err)
		}
	}
	return nil
}

// ruleValidID checks whether the permission ID is valid
// 检查权限 ID 是否合法
func ruleValidID(p *Permission) error {
	if !permissionIDPattern.MatchString(p.ID) {
		return errors.New("malformed id")
	}
	if p.Source == "" {
		return errors.New("empty source")
	}
	return nil
}

// ruleValidType checks whether the permission type is valid
// 检查权限类型是否合法
func ruleValidType(p *Permission) error {
	switch p.Type {
	case PermissionTypeSystem, PermissionTypeUser:
		return nil
	default:
		return fmt.Errorf("unknown type %d", p.Type)
	}
}

// ruleSystemNoConfirm enforces that system permissions are granted without asking the user
// 系统权限一律不需要用户确认
func ruleSystemNoConfirm(p *Permission) error {
	if p.IsSystem() && p.NeedUserConfirm {
		return errors.New("system permission must not need user confirmation")
	}
	return nil
}

// ruleGIDNotInComponentRange keeps permission groups away from component IDs,
// so a permission group can never be confused with a component's own group.
// 权限组不能落在组件 UID/GID 区间内
func ruleGIDNotInComponentRange(p *Permission) error {
	cfg := config.Get()
	if p.GID >= cfg.ComponentIDMin && p.GID <= cfg.ComponentIDMax {
		return fmt.Errorf("gid %d is inside the component id range [%d, %d]",
			p.GID, cfg.ComponentIDMin, cfg.ComponentIDMax)
	}
	return nil
}

// ruleBuiltinPrefix requires builtin IDs to match their type (doc 4.1)
// 内置系统权限使用 nervus.system.perm.，内置用户权限使用 nervus.perm.
func ruleBuiltinPrefix(p *Permission) error {
	if !p.IsBuiltin() {
		return nil
	}
	prefix := UserPermissionPrefix
	if p.IsSystem() {
		prefix = SystemPermissionPrefix
	}
	if !strings.HasPrefix(p.ID, prefix) {
		return fmt.Errorf("builtin %s permission must start with %q", p.Type, prefix)
	}
	return nil
}

// ruleCustomNotReserved prevents services from declaring IDs in a reserved namespace
// 防止服务用保留前缀冒充内置权限
func ruleCustomNotReserved(p *Permission) error {
	if p.IsBuiltin() {
		return nil
	}
	for _, prefix := range reservedPermissionPrefixes {
		if strings.HasPrefix(p.ID, prefix) {
			return fmt.Errorf("reserved prefix %q", prefix)
		}
	}
	return nil
}

// ruleCustomNoGroup enforces that all group-controlled permissions are builtin (doc 4.1)
// 所有用户组控制型权限都是内置权限
func ruleCustomNoGroup(p *Permission) error {
	if !p.IsBuiltin() && p.IsGroupControlled() {
		return errors.New("custom permission cannot be group-controlled")
	}
	return nil
}

// ruleCustomNamespace requires custom IDs to live under the declaring package,
// so one package cannot squat on another's permission name.
// 自定义权限 ID 必须以声明它的服务所属的包 ID 开头，防止抢注别的包的权限名
func ruleCustomNamespace(p *Permission) error {
	if p.IsBuiltin() {
		return nil
	}
	if err := validatePermissionIDForPackage(PackageOf(p.Source), p.ID); err != nil {
		return err
	}
	return nil
}
