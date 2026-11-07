package registry

// ComponentType represents the type of component
type ComponentType int

const (
	ComponentTypeApp ComponentType = iota
	ComponentTypeService
)

// String returns the string representation of ComponentType
func (t ComponentType) String() string {
	switch t {
	case ComponentTypeApp:
		return "app"
	case ComponentTypeService:
		return "service"
	default:
		return "unknown"
	}
}

// Component roles, see manifest.sig signatures.role
const (
	RoleDeveloper = iota
	RolePlatform
)

type ComponentRole int

func (r ComponentRole) String() string {
	switch r {
	case RoleDeveloper:
		return "developer"
	case RolePlatform:
		return "platform"
	default:
		return "unknown"
	}
}

// Component represents a registered component in NervusOS
type Component struct {
	ID                   string            `json:"id"`
	Type                 ComponentType     `json:"type"`
	Entry                string            `json:"entry"`
	WorkDir              string            `json:"work_dir"`
	DataDir              string            `json:"data_dir"`
	UID                  int32             `json:"uid"`
	GID                  int32             `json:"gid"`
	RequestedPermissions []string          `json:"requested_permissions"` // declared at install, never extended later / 安装时申请，之后不再增加
	PermissionAdditions  []AddedPermission `json:"permission_additions"`  // services only / 仅服务组件
	IsAvailable          bool              `json:"is_available"`
}

// KernelReservedPrefix may not be used by any package or component id
// 内核保留的命名空间，包和组件都不得使用
const KernelReservedPrefix = "nervud."
