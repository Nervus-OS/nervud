package registry

// GIDs of builtin permission groups.
// Camera uses the Ubuntu Desktop video group; the 2000x range is defined by NervusOS.
// 内置权限组的 GID：摄像头沿用 Ubuntu Desktop 的 video 组（44），其余 2000x 为 NervusOS 自定义组。
// 分发版要改某个组，只改这里的数字即可；新增权限组在下面追加一行常量。
const (
	GIDBluetooth     int32 = 20000 // Bluetooth
	GIDCamera        int32 = 44    // Camera (Ubuntu's video group)
	GIDDataPath      int32 = 20002 // Component shared data path
	GIDDownloads     int32 = 20003 // Shared download directory
	GIDReadConfig    int32 = 20004 // Read system configuration (user permissions)
	GIDSystemReadCfg int32 = 20005 // Read system configuration (system permissions)
	GIDDevice        int32 = 20006 // Device-related system permissions
	GIDServiceShared int32 = 20007 // System service shared directory

	// GIDDisplay is not a permission. App components join it at launch so they can use
	// displayd.sock, which is readable and writable only by root and the display group.
	// 不是权限：App 组件启动时加入 display 组，用于访问 displayd.sock
	GIDDisplay int32 = 20008
)

// Names written to /etc/group, for human readers only
// 写进 /etc/group 的组名，仅方便人阅读
const (
	GroupNameBluetooth     = "nervus_bluetooth"
	GroupNameCamera        = "video"
	GroupNameDataPath      = "nervus_datapath"
	GroupNameDownloads     = "nervus_downloads"
	GroupNameReadConfig    = "nervus_read_config"
	GroupNameSystemReadCfg = "nervus_system_read_config"
	GroupNameDevice        = "nervus_device"
	GroupNameServiceShared = "nervus_service_shared"
	GroupNameDisplay       = "nervus_display"
)

// Builtin permission IDs
// User-facing names and descriptions are not kept in the kernel;
// UI translates them by permission ID.
// 内置权限 ID；界面上显示的名称和描述不放在内核里，由界面按权限 ID 做多语言翻译
const (
	// PermBluetooth User-group controlled permissions
	PermBluetooth           = "nervus.perm.bluetooth"             // Bluetooth access
	PermCamera              = "nervus.perm.camera"                // Camera access
	PermDataPath            = "nervus.perm.datapath"              // Component shared data path access
	PermDownloads           = "nervus.perm.downloads"             // Shared download directory access
	PermReadConfig          = "nervus.perm.read_config"           // Read system configuration
	PermSystemReadConfig    = "nervus.system.perm.read_config"    // Read system configuration (system components)
	PermSystemRoot          = "nervus.system.perm.root"           // System administrator permissions (root group, no path)
	PermSystemDev           = "nervus.system.perm.dev"            // Device-related system permissions
	PermSystemServiceShared = "nervus.system.perm.service_shared" // System service shared directory

	// PermComponentExecute Other builtin permissions
	PermComponentExecute         = "nervus.perm.component.execute"          // Run components from other packages
	PermComponentStop            = "nervus.perm.component.stop"             // Stop components from other packages
	PermComponentStatus          = "nervus.perm.component.status"           // Get status of components from other packages
	PermSystemComponentExecute   = "nervus.system.perm.component.execute"   // Run components (system components)
	PermSystemComponentStop      = "nervus.system.perm.component.stop"      // Stop components (system components)
	PermSystemComponentStatus    = "nervus.system.perm.component.status"    // Get component status (system components)
	PermStartOnBoot              = "nervus.perm.start_on_boot"              // Automatically start on system boot
	PermSystemStartOnBoot        = "nervus.system.perm.start_on_boot"       // Automatically start on system boot (system components)
	PermAlwaysOn                 = "nervus.perm.always_on"                  // Automatically restart after exit
	PermSystemAlwaysOn           = "nervus.system.perm.always_on"           // Automatically restart after exit (system components)
	PermSystemConfirmPermission  = "nervus.system.perm.confirm_permission"  // Confirm permissions of other components
	PermSystemComponentRegistry  = "nervus.system.perm.component_registry"  // Access component registry via virtual service
	PermSystemPermissionRegistry = "nervus.system.perm.permission_registry" // Access permission registry via virtual service
)

// permissionBits are the rwx bits used in the ACL path table below
// 下面 ACL 路径表使用的访问位
type permissionBits int

const (
	permRead    permissionBits = 4
	permWrite   permissionBits = 2
	permExecute permissionBits = 1
	permRW      permissionBits = permRead | permWrite
	permRWX     permissionBits = permRead | permWrite | permExecute
)

// pathType decides how a path pattern is expanded
// 路径条目的展开方式
type pathType int

const (
	// pathMatches: filepath.Glob, ACL only where the path exists
	// 按通配符展开，只对已存在的路径加 ACL
	pathMatches pathType = iota
	// pathKernelDir: a directory owned by the kernel, created if missing, and opened
	// to the permission group through an inherited ACL
	// 内核创建并持有的目录，缺失时创建，通过默认 ACL 放开给权限组
	pathKernelDir
	// pathDeviceTree: walk the given directory and grant on every char/block device node,
	// skipping directories. Used by nervus.system.perm.dev.
	// 递归遍历目录，只对字符/块设备节点授权，跳过目录
	pathDeviceTree
)

// pathRule is the static rule written in the builtin permission table.
// expandRule turns it into concrete paths.
// 权限表里固定的静态规则，由 expandRule 展开成具体路径
type pathRule struct {
	path string
	kind pathType
	bits permissionBits
}

// builtinPermissionPaths is the file side of the builtin permission table.
// The GID comes from the permission entry, not from here.
// /sys and /proc paths are intentionally absent: they do not support POSIX ACLs,
// so the kernel filesystems' own read permissions apply.
// 内置权限的路径表；GID 取自权限条目本身。sysfs/procfs 不支持 ACL，故不列入。
var builtinPermissionPaths = map[string][]pathRule{
	PermBluetooth: {
		{path: "/dev/rfcomm*", kind: pathMatches, bits: permRW},
		{path: "/dev/hci*", kind: pathMatches, bits: permRW},
		{path: "/var/lib/bluetooth/", kind: pathMatches, bits: permRW},
		{path: "/run/dbus/system_bus_socket", kind: pathMatches, bits: permRW},
	},
	PermCamera: {
		{path: "/dev/video*", kind: pathMatches, bits: permRW},
	},
	PermDataPath: {
		{path: "/var/lib/nervus/data/", kind: pathKernelDir, bits: permRWX},
	},
	PermDownloads: {
		{path: "/var/lib/nervus/data/downloads/", kind: pathKernelDir, bits: permRWX},
	},
	PermReadConfig: {
		{path: "/etc/nervus/config.yaml", kind: pathMatches, bits: permRead},
	},
	PermSystemReadConfig: {
		{path: "/etc/nervus/config.yaml", kind: pathMatches, bits: permRead},
	},
	PermSystemDev: {
		{path: "/dev", kind: pathDeviceTree, bits: permRW},
	},
	PermSystemServiceShared: {
		{path: "/var/lib/nervus/service/system/", kind: pathKernelDir, bits: permRWX},
	},
	// PermSystemRoot grants the root group and no path, so it has no entry here
	// nervus.system.perm.root 只加入 root 组，不对任何路径加 ACL
}

// builtinPermissions is the builtin permission table.
// To add a builtin permission, add its ID constant and GID/name above,
// append one row here, and add its paths to builtinPermissionPaths.
// 内置权限表；新增内置权限时，在上面加 ID 常量和 GID/组名，在这里追加一行，
// 并在 builtinPermissionPaths 中补充它的路径
var builtinPermissions = []Permission{
	// User-group controlled
	// 用户组控制型：通过 GID 与文件 ACL 控制访问
	groupControlled(PermBluetooth, PermissionTypeUser, GIDBluetooth, true),
	groupControlled(PermCamera, PermissionTypeUser, GIDCamera, true),
	groupControlled(PermDataPath, PermissionTypeUser, GIDDataPath, true),
	groupControlled(PermDownloads, PermissionTypeUser, GIDDownloads, false),
	groupControlled(PermReadConfig, PermissionTypeUser, GIDReadConfig, true),
	groupControlled(PermSystemReadConfig, PermissionTypeSystem, GIDSystemReadCfg, false),
	groupControlled(PermSystemRoot, PermissionTypeSystem, GIDRoot, false),
	groupControlled(PermSystemDev, PermissionTypeSystem, GIDDevice, false),
	groupControlled(PermSystemServiceShared, PermissionTypeSystem, GIDServiceShared, false),

	// Service controlled
	// 服务控制型：由内核虚拟服务自行检查
	serviceControlled(PermComponentExecute, PermissionTypeUser, true),
	serviceControlled(PermComponentStop, PermissionTypeUser, true),
	serviceControlled(PermComponentStatus, PermissionTypeUser, true),
	serviceControlled(PermSystemComponentExecute, PermissionTypeSystem, false),
	serviceControlled(PermSystemComponentStop, PermissionTypeSystem, false),
	serviceControlled(PermSystemComponentStatus, PermissionTypeSystem, false),
	serviceControlled(PermStartOnBoot, PermissionTypeUser, true),
	serviceControlled(PermSystemStartOnBoot, PermissionTypeSystem, false),
	serviceControlled(PermAlwaysOn, PermissionTypeUser, true),
	serviceControlled(PermSystemAlwaysOn, PermissionTypeSystem, false),
	serviceControlled(PermSystemConfirmPermission, PermissionTypeSystem, false),
	serviceControlled(PermSystemComponentRegistry, PermissionTypeSystem, false),
	serviceControlled(PermSystemPermissionRegistry, PermissionTypeSystem, false),
}

// builtinPermissionGroups lists every group nervud must ensure in /etc/group
// 需要确保存在于 /etc/group 中的组
var builtinPermissionGroups = []struct {
	name string
	gid  int32
}{
	{GroupNameBluetooth, GIDBluetooth},
	{GroupNameCamera, GIDCamera},
	{GroupNameDataPath, GIDDataPath},
	{GroupNameDownloads, GIDDownloads},
	{GroupNameReadConfig, GIDReadConfig},
	{GroupNameSystemReadCfg, GIDSystemReadCfg},
	{GroupNameDevice, GIDDevice},
	{GroupNameServiceShared, GIDServiceShared},
	{GroupNameDisplay, GIDDisplay},
}

// groupControlled builds a builtin permission controlled by a user group
// 构造一个通过用户组控制的内置权限
func groupControlled(id string, permType PermissionType, gid int32, needUserConfirm bool) Permission {
	return Permission{
		ID:              id,
		Type:            permType,
		Source:          BuiltinPermissionSource,
		GID:             gid,
		NeedUserConfirm: needUserConfirm,
	}
}

// serviceControlled builds a builtin permission checked by the virtual service itself.
// Using this helper avoids leaving GID at its zero value, which would mean the root group.
// 构造一个通过虚拟服务自行检查的内置权限，并避免 GID 留空成 0
func serviceControlled(id string, permType PermissionType, needUserConfirm bool) Permission {
	return groupControlled(id, permType, NoGID, needUserConfirm)
}
