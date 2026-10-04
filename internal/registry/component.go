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

// Component represents a registered component in NervusOS
type Component struct {
	ID                  string                `json:"id"`
	Type                ComponentType         `json:"type"`
	Entry               string                `json:"entry"`
	Permissions         []ComponentPermission `json:"permissions"`
	WorkDir             string                `json:"work_dir"`
	DataDir             string                `json:"data_dir"`
	UID                 int32                 `json:"uid"`
	Role                string                `json:"role"` // developer or platform
	PermissionAdditions []AddedPermission     `json:"permission_additions"`
	PackageID           string                `json:"package_id"`
	IsAvailable         bool                  `json:"is_available"`
}

// ComponentPermission indicates whether component permissions are granted.
type ComponentPermission struct {
	ID          string `json:"id"`
	IsConfirmed bool   `json:"is_confirmed"`
}

// AddedPermission represents a custom permission declared by a service component
type AddedPermission struct {
	ID               string `json:"id"`
	SystemPermission bool   `json:"system_permission"`
	NeedUserConfirm  bool   `json:"need_user_confirm"`
	Description      string `json:"description"` // To user
}
