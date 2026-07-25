package authority

import (
	"fmt"
	"path"
	"strings"
)

// Invariants 是一组无权豁免的系统级硬约束
//
// 分工：策略回答此刻、对这个 subject、允不允许 可配置
// 可随部署变化；Invariants 回答这个系统里什么永远不成立 不可配置、不接受
// 任何豁免。例：某 App 能不能建数据目录是策略
// 目录必须在 DataRoot 之下和属主 UID 不得为 0是Invariants
//
// 所有字段在 New 时冻结，运行期只读；没有任何导出的 setter
type Invariants struct {
	DataRoot    string // Package 私有数据根，如 /var/lib/nervus/package-data
	PackageRoot string // 动态安装的 Package 根，如 /var/lib/nervus/packages
	// SystemPackageRoot 是系统镜像内置 Package 的只读根，
	// 如 /usr/lib/nervus/system-packages。
	//
	// 【必须与 PackageRoot 分开】：两类包的代码住在完全不同的位置，而且布局
	// 也不同——动态安装是 <root>/<pkg>/<version>/，系统镜像是 <root>/<pkg>/
	// （无版本子目录，跟随整镜像 OTA，不存在多版本共存）。
	//
	// 起进程时的路径包含校验必须认这两个根中的任意一个，否则系统包的可执行
	// 文件会被判成「逃出 PackageRoot」而拒绝启动。
	SystemPackageRoot string
	// UserDataRoot 是【跨 Package 共享】的用户文档区，如 /var/lib/nervus/user-data。
	//
	// 与 DataRoot 的区别是本质性的：DataRoot 下每个包一个 0700 的私有目录，谁也
	// 看不见谁；UserDataRoot 是一块公共地，文件管理器、文件选择器与任何声明了
	// perm.storage.user 的包共同读写同一批文件——"用户的文档"这个概念要求它们
	// 看到的是同一份东西，私有目录表达不了。
	//
	// 权限模型是 sticky（01777，语义同 /tmp）：任何有权进来的包都能创建文件、
	// 能读别人的文件，但【只能删自己的】。
	//
	// [v1 取舍] 这意味着没有按包隔离的读保护——等价于 Android scoped storage
	// 之前的共享外部存储。选它是因为 v1 需要"文件管理器能管、选择器能选、别的
	// app 能打开"这条最基本的链路先成立，而按包隔离需要每包一个 GID +
	// SupplementaryGroups 或 bind mount，那是 v2 的工作量。
	//
	// 只有声明了 perm.storage.user 的包才会拿到它（见 service.readWritePaths）；
	// 没声明的包在 ProtectSystem=strict 下连写都写不进去。
	UserDataRoot string
	MinAppUID    uint32 // App UID/GID 下界，低于此值属系统保留
	MaxAppUID    uint32
}

// DefaultInvariants 是生产镜像的固定取值。不做成配置文件读取
//
// DataRoot 用 package-data 而非 data：与 的路径表一致，名字也更能表达
// 这是 Package 私有数据而非某个通用 data 目录
func DefaultInvariants() *Invariants {
	return &Invariants{
		DataRoot:          "/var/lib/nervus/package-data",
		PackageRoot:       "/var/lib/nervus/packages",
		SystemPackageRoot: "/usr/lib/nervus/system-packages",
		UserDataRoot:      "/var/lib/nervus/user-data",
		MinAppUID:         20000, // 避开发行版的系统和普通用户段
		MaxAppUID:         59999,
	}
}

// CheckUID 拒绝 root 与保留段之外的一切 App 身份
//
// UID 0 是 Linux 特殊 root 身份，App UID 0 永远禁止；除 UID 0 外
// UID 数值大小不代表权限高低 - 所以这里不是越大越安全，只是段位隔离
// GID 复用同一区段与本检查
func (inv *Invariants) CheckUID(uid uint32) error {
	if uid == 0 {
		return fmt.Errorf("%w: uid 0 is never permitted for app identity", ErrInvariantViolated)
	}
	if uid < inv.MinAppUID || uid > inv.MaxAppUID {
		return fmt.Errorf("%w: uid %d outside app range [%d,%d]",
			ErrInvariantViolated, uid, inv.MinAppUID, inv.MaxAppUID)
	}
	return nil
}

// CheckContainedInCodeRoot 校验 p 位于【任一】代码根之内（动态安装根或系统镜像根）。
//
// 起进程的路径校验用它而不是 CheckContained(p, PackageRoot)：系统镜像包的
// 可执行文件住在 SystemPackageRoot 下，只认 PackageRoot 会把它们全判成逃逸。
//
// 两个根都不匹配时返回针对 PackageRoot 的那个错误——它是更常见的情形，
// 错误信息里给出的对比根也更可能是调用方想要的那个。
func (inv *Invariants) CheckContainedInCodeRoot(p string) error {
	if inv.SystemPackageRoot != "" {
		if err := inv.CheckContained(p, inv.SystemPackageRoot); err == nil {
			return nil
		}
	}
	return inv.CheckContained(p, inv.PackageRoot)
}

// CheckContained 校验路径 p 严格位于路径 root 之内（root 本身不算之内）
func (inv *Invariants) CheckContained(p, root string) error {
	_, err := containedRel(p, root)
	return err
}

// containedRel 校验 p 严格位于 root 之内，并返回相对 root 的斜杠相对路径
// 校验规则三重防线，缺一不可
// ：
//  1. 必须绝对路径 - 相对路径的含义取决于进程 cwd，而 cwd 可被 systemd 单元
//     甚至运行期 chdir 改变，等于把安全边界交给外部状态
//  2. Clean 后做前缀比较，且前缀必须以 "/" 结尾 - 否则 /var/lib/nervus/package-data-evil
//     会通过 /var/lib/nervus/package-data 的朴素前缀检查；".." 也在 Clean 中被折叠
//     折叠后逃出 root 的路径同样通不过前缀比较
//
// 注意：本函数是纯字符串运算，挡不住 symlink 逃逸。真正的保证必须
// 由内核完成 - 执行路径用 openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) 解析
// 见 ops_linux.go。字符串检查只是快速失败的第一道，不是最终保证
func containedRel(p, root string) (string, error) {
	if !path.IsAbs(p) {
		return "", fmt.Errorf("%w: path %q must be absolute", ErrInvariantViolated, p)
	}
	cleaned := path.Clean(p)
	prefix := path.Clean(root) + "/"
	if !strings.HasPrefix(cleaned, prefix) {
		return "", fmt.Errorf("%w: path %q escapes root %q", ErrInvariantViolated, cleaned, root)
	}
	return cleaned[len(prefix):], nil
}
