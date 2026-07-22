package authority

import (
	"fmt"
	"path"
	"strings"
)

// Invariants 是一组无权豁免的系统级硬约束
//
// 分工：策略回答“此刻、对这个 subject、允不允许”  可配置
// 可随部署变化；Invariants 回答“这个系统里什么永远不成立”  不可配置、不接受
// 任何豁免。例：某 App 能不能建数据目录是策略
// 目录必须在 DataRoot 之下和属主 UID 不得为 0是Invariants
//
// 所有字段在 New 时冻结，运行期只读；没有任何导出的 setter
type Invariants struct {
	DataRoot    string // App 私有数据根，如 /var/lib/nervus/data
	PackageRoot string // 已安装 Package 根，如 /var/lib/nervus/packages
	MinAppUID   uint32 // App UID/GID 下界，低于此值属系统保留
	MaxAppUID   uint32
}

// DefaultInvariants 是生产镜像的固定取值。不做成配置文件读取
func DefaultInvariants() *Invariants {
	return &Invariants{
		DataRoot:    "/var/lib/nervus/data",
		PackageRoot: "/var/lib/nervus/packages",
		MinAppUID:   20000, // 避开发行版的系统和普通用户段
		MaxAppUID:   59999,
	}
}

// CheckUID 拒绝 root 与保留段之外的一切 App 身份
//
// UID 0 是 Linux 特殊 root 身份，App UID 0 永远禁止；除 UID 0 外
// UID 数值大小不代表权限高低——所以这里不是「越大越安全」，只是段位隔离
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

// CheckContained 校验路径 p 严格位于路径 root 之内（root 本身不算之内）
func (inv *Invariants) CheckContained(p, root string) error {
	_, err := containedRel(p, root)
	return err
}

// containedRel 校验 p 严格位于 root 之内，并返回相对 root 的斜杠相对路径
// 校验规则三重防线，缺一不可
//：
//  1. 必须绝对路径——相对路径的含义取决于进程 cwd，而 cwd 可被 systemd 单元
//     甚至运行期 chdir 改变，等于把安全边界交给外部状态
//  2. Clean 后做前缀比较，且前缀必须以 "/" 结尾——否则 /var/lib/nervus/data-evil
//     会通过 /var/lib/nervus/data 的朴素前缀检查；".." 也在 Clean 中被折叠
//     折叠后逃出 root 的路径同样通不过前缀比较
//
// 注意：本函数是纯字符串运算，挡不住 symlink 逃逸。真正的保证必须
// 由内核完成——执行路径用 openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) 解析
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
