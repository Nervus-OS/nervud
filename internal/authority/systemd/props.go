// 本文件是 StartTransientUnit 的属性构造与本地白名单校验（应用层架构决策 §5.2）。
//
// 这里只做纯数据变换（UnitSpec -> []property）与形状校验，不发起任何 D-Bus 调用，
// 因此可在没有 systemd 的环境下完整单测——把「哪些 sandbox/limit 属性、什么类型」
// 这一层与「真正打 D-Bus」（systemd.go）分开，是为了让最容易写错的属性映射有回归锁。
//
// 依赖边界：本子包是【全仓库唯一】允许 import github.com/godbus/dbus/v5 的地方
// （.golangci.yml 的 godbus-boundary depguard 规则），它属于 nervud 的 TCB，
// 按内核依赖对待（固定版本、提交 go.sum、纳入 SBOM）。
package systemd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
)

var (
	// ErrInvalidUnitName unit 名不符合 nervus-<pkg>-<comp>.service 白名单
	ErrInvalidUnitName = errors.New("systemd: invalid transient unit name")
	// ErrInvalidExec ExecStart 路径非法（空/非绝对/含控制字符）
	ErrInvalidExec = errors.New("systemd: invalid exec path")
	// ErrInvalidEnv 环境变量条目非法（无 '='、键非法、含控制字符）
	ErrInvalidEnv = errors.New("systemd: invalid environment entry")
	// ErrInvalidWorkingDir WorkingDirectory 非法（空/非绝对）
	ErrInvalidWorkingDir = errors.New("systemd: invalid working directory")
)

// Runtime 与 pkgregistry.Runtime 对应；systemd 子包不 import pkgregistry（避免
// 依赖倒挂），用自己的小枚举，由 authority 翻译
type Runtime uint8

const (
	RuntimeNative Runtime = iota
	RuntimeJVM
)

// Limits 是传给 systemd 的资源上限（应用层架构决策 §3.4/§5.2）。零值表示不设该项
type Limits struct {
	MemoryMaxBytes uint64
	// CPUQuotaPercent 是 CPU 配额百分比（100 = 一个核）。转成 CPUQuotaPerSecUSec
	CPUQuotaPercent uint32
	TasksMax        uint64
}

// Sandbox 是进程的隔离 profile（应用层架构决策 §5.2）。字段直接映射 systemd 属性；
// 由 authority 按 trust/组件类型填好后传入，systemd 子包只负责把它翻成 D-Bus 属性
type Sandbox struct {
	// ReadWritePaths 在 ProtectSystem=strict 下【必须】列出组件可写的目录——strict
	// 把整个文件系统设为只读，不显式放行则连自己的私有数据目录都写不了
	ReadWritePaths []string
	// ReadOnlyPaths / InaccessiblePaths 让「其它 Package 的目录」不可读写
	ReadOnlyPaths     []string
	InaccessiblePaths []string
}

// UnitSpec 是一次 StartTransientUnit 的完整输入
type UnitSpec struct {
	Name        string   // nervus-<pkgid>-<compid>.service
	Description string   // 人类可读，仅用于 systemd status 展示
	ExecPath    string   // 绝对路径：native=包内 ELF；jvm=/usr/lib/nervus/jre/bin/java
	Args        []string // ExecStart 参数（不含 argv[0]）
	UID         uint32
	GID         uint32
	WorkingDir  string // /var/lib/nervus/package-data/<id>
	Env         []string
	Limits      Limits
	Sandbox     Sandbox
}

// property 是 StartTransientUnit 的一条属性（D-Bus 结构 (sv)）
type property struct {
	Name  string
	Value dbus.Variant
}

// execStartItem 对应 ExecStart 的 D-Bus 类型 a(sasb)：路径、argv（含 argv[0]）、
// uncleanIsFailure。argv[0] 按惯例填 ExecPath 本身
type execStartItem struct {
	Path             string
	Argv             []string
	UncleanIsFailure bool
}

// restrictSet 对应 SystemCallFilter / RestrictAddressFamilies 的 D-Bus 类型 (bas)：
// whitelist 标志 + 名称列表
type restrictSet struct {
	Whitelist bool
	Values    []string
}

// validateSpec 做发起 D-Bus 前的本地白名单校验（§5.1「本地白名单校验，不接受调用方
// 传任意 systemd property」）。返回 nil 才允许构造属性
func validateSpec(spec UnitSpec) error {
	if !validUnitName(spec.Name) {
		return fmt.Errorf("%w: %q", ErrInvalidUnitName, spec.Name)
	}
	if !isAbsClean(spec.ExecPath) {
		return fmt.Errorf("%w: %q", ErrInvalidExec, spec.ExecPath)
	}
	if !isAbsClean(spec.WorkingDir) {
		return fmt.Errorf("%w: %q", ErrInvalidWorkingDir, spec.WorkingDir)
	}
	for _, a := range spec.Args {
		if strings.ContainsAny(a, "\x00\n") {
			return fmt.Errorf("%w: arg contains control char", ErrInvalidExec)
		}
	}
	for _, e := range spec.Env {
		if !validEnvEntry(e) {
			return fmt.Errorf("%w: %q", ErrInvalidEnv, e)
		}
	}
	return nil
}

// BuildProperties 把 UnitSpec 翻成 StartTransientUnit 的属性数组
//
// 属性集固定（§5.2）：调用方只能通过 UnitSpec 的受限字段影响 exec/uid/limits/沙箱
// 路径，不能注入任意 systemd property。沙箱硬项（NoNewPrivileges/ProtectSystem=strict/
// PrivateDevices/…）无条件加上，不给放宽入口
func BuildProperties(spec UnitSpec) ([]property, error) {
	if err := validateSpec(spec); err != nil {
		return nil, err
	}

	argv := append([]string{spec.ExecPath}, spec.Args...)
	props := []property{
		{"Description", dbus.MakeVariant(spec.Description)},
		{"ExecStart", dbus.MakeVariant([]execStartItem{{Path: spec.ExecPath, Argv: argv, UncleanIsFailure: false}})},
		// 数字 UID/GID 以字符串形式传给 systemd（User/Group 接受数字字符串）
		{"User", dbus.MakeVariant(fmt.Sprintf("%d", spec.UID))},
		{"Group", dbus.MakeVariant(fmt.Sprintf("%d", spec.GID))},
		{"WorkingDirectory", dbus.MakeVariant(spec.WorkingDir)},

		// ---- §5.2 通用沙箱硬项（无条件）----
		{"NoNewPrivileges", dbus.MakeVariant(true)},
		{"ProtectSystem", dbus.MakeVariant("strict")},
		{"ProtectHome", dbus.MakeVariant("yes")},
		{"PrivateTmp", dbus.MakeVariant(true)},
		{"PrivateDevices", dbus.MakeVariant(true)},
		{"DevicePolicy", dbus.MakeVariant("closed")},
		{"ProtectKernelTunables", dbus.MakeVariant(true)},
		{"ProtectKernelModules", dbus.MakeVariant(true)},
		{"RestrictSUIDSGID", dbus.MakeVariant(true)},
		{"RestrictRealtime", dbus.MakeVariant(true)},
		// SystemCallFilter=@system-service（whitelist）已排除 @mount/@module/@raw-io/
		// @privileged/@debug（§5.2）
		{"SystemCallFilter", dbus.MakeVariant(restrictSet{Whitelist: true, Values: []string{"@system-service"}})},
		// 仅允许 UNIX/INET/INET6：堵住 raw/packet socket 等
		{"RestrictAddressFamilies", dbus.MakeVariant(restrictSet{Whitelist: true, Values: []string{"AF_UNIX", "AF_INET", "AF_INET6"}})},
	}

	if len(spec.Env) > 0 {
		props = append(props, property{"Environment", dbus.MakeVariant(spec.Env)})
	}
	if len(spec.Sandbox.ReadWritePaths) > 0 {
		props = append(props, property{"ReadWritePaths", dbus.MakeVariant(spec.Sandbox.ReadWritePaths)})
	}
	if len(spec.Sandbox.ReadOnlyPaths) > 0 {
		props = append(props, property{"ReadOnlyPaths", dbus.MakeVariant(spec.Sandbox.ReadOnlyPaths)})
	}
	if len(spec.Sandbox.InaccessiblePaths) > 0 {
		props = append(props, property{"InaccessiblePaths", dbus.MakeVariant(spec.Sandbox.InaccessiblePaths)})
	}

	// ---- 资源上限（零值不设）----
	if spec.Limits.MemoryMaxBytes > 0 {
		props = append(props, property{"MemoryMax", dbus.MakeVariant(spec.Limits.MemoryMaxBytes)})
	}
	if spec.Limits.TasksMax > 0 {
		props = append(props, property{"TasksMax", dbus.MakeVariant(spec.Limits.TasksMax)})
	}
	if spec.Limits.CPUQuotaPercent > 0 {
		// CPUQuotaPerSecUSec：每秒可用 CPU 微秒数。100% = 1 秒 = 1_000_000us
		usec := uint64(spec.Limits.CPUQuotaPercent) * 10_000
		props = append(props, property{"CPUQuotaPerSecUSec", dbus.MakeVariant(usec)})
	}

	return props, nil
}

// ---- 本地白名单校验 ------------------------------------------------------

// validUnitName 报告 name 是否是安全的瞬态 unit 名：必须以 nervus- 前缀 +
// .service 后缀，中间只允许 [a-z0-9._-]，无斜杠、无路径分隔、长度有界。
//
// 前缀锁定为 nervus- 是为了让 nervud 起的瞬态 unit 与系统其它 unit 在命名空间上
// 隔离，StopUnit 时也不可能误停一个系统关键 unit
func validUnitName(name string) bool {
	const prefix = "nervus-"
	const suffix = ".service"
	if len(name) < len(prefix)+len(suffix)+1 || len(name) > 255 {
		return false
	}
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	mid := name[:len(name)-len(suffix)] // 去掉 .service，含前缀
	for i := 0; i < len(mid); i++ {
		c := mid[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
			// ok
		default:
			return false
		}
	}
	return true
}

// isAbsClean 报告 p 是否是一个绝对、无控制字符的 Linux 路径
func isAbsClean(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") {
		return false
	}
	return !strings.ContainsAny(p, "\x00\n")
}

// validEnvEntry 报告 e 是否是安全的 "KEY=VALUE"：含 '='，键为 [A-Za-z_][A-Za-z0-9_]*，
// 整条无 NUL/换行（防注入进 systemd unit）
func validEnvEntry(e string) bool {
	if strings.ContainsAny(e, "\x00\n") {
		return false
	}
	i := strings.IndexByte(e, '=')
	if i <= 0 {
		return false
	}
	key := e[:i]
	for j := 0; j < len(key); j++ {
		c := key[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
			// ok（首尾均可）
		case j > 0 && c >= '0' && c <= '9':
			// ok（数字不能作首字符）
		default:
			return false
		}
	}
	return true
}
