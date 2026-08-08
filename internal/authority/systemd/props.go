// 本文件是 StartTransientUnit 的属性构造与本地白名单校验.
//
// 这里只做纯数据变换 (UnitSpec -> []property) 与形状校验, 不发起任何 D-Bus 调用,
// 因此可在没有 systemd 的环境下完整单测 - 把哪些 sandbox/limit 属性, 什么类型
// 这一层与真正打 D-Bus (systemd.go) 分开, 是为了让最容易写错的属性映射有回归锁.
//
// 依赖边界: 本子包是全仓库唯一允许 import github.com/godbus/dbus/v5 的地方
//
//	(.golangci.yml 的 godbus-boundary depguard 规则), 它属于 nervud 的 TCB,
//
// 按内核依赖对待 (固定版本, 提交 go.sum, 纳入 SBOM).
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
	// ErrInvalidExec ExecStart 路径非法 (空/非绝对/含控制字符)
	ErrInvalidExec = errors.New("systemd: invalid exec path")
	// ErrInvalidEnv 环境变量条目非法 (无 '=', 键非法, 含控制字符)
	ErrInvalidEnv = errors.New("systemd: invalid environment entry")
	// ErrInvalidWorkingDir WorkingDirectory 非法 (空/非绝对)
	ErrInvalidWorkingDir = errors.New("systemd: invalid working directory")
)

// Runtime 与 pkgregistry.Runtime 对应; systemd 子包不 import pkgregistry (避免
// 依赖倒挂), 用自己的小枚举, 由 authority 翻译
type Runtime uint8

const (
	RuntimeNative Runtime = iota
	RuntimeJVM
)

// Limits 是传给 systemd 的资源上限. 零值表示不设该项
type Limits struct {
	MemoryMaxBytes uint64
	// CPUQuotaPercent 是 CPU 配额百分比 (100 = 一个核). 转成 CPUQuotaPerSecUSec
	CPUQuotaPercent uint32
	TasksMax        uint64
}

// Sandbox 是进程的隔离 profile. 字段直接映射 systemd 属性;
// 由 authority 按 trust/组件类型填好后传入, systemd 子包只负责把它翻成 D-Bus 属性
type Sandbox struct {
	// ReadWritePaths 在 ProtectSystem=strict 下必须列出组件可写的目录 - strict
	// 把整个文件系统设为只读, 不显式放行则连自己的私有数据目录都写不了
	ReadWritePaths []string
	// ReadOnlyPaths / InaccessiblePaths 让其它 Package 的目录不可读写
	ReadOnlyPaths     []string
	InaccessiblePaths []string

	// AllowDeviceAccess 放开该 unit 对宿主设备节点的访问: PrivateDevices 关闭,
	// DevicePolicy 由 closed 放宽为 auto.
	//
	// 为什么需要这个口子: 默认的 PrivateDevices=true 给进程挂一个只含
	// null/zero/full/random/urandom/tty 的私有 /dev, DevicePolicy=closed 再把
	// cgroup 设备白名单收紧到同一批. 两者叠加后, 进程无论以什么 UID 运行
	// 都看不到 /dev/ttyUSB*, CAN, SPI, i2c - 也就是说驱动机器人硬件的
	// 系统服务在默认沙箱里根本起不到作用. 提权到 root 并不能绕开这一点:
	// 这是 mount namespace 与 cgroup 设备控制器的限制, 不是 DAC 权限问题.
	//
	// 只应对系统镜像内置的 Provider 打开 (见 service.buildStartReq).
	// 动态安装的包永远拿不到它 - 那等于把设备节点交给任意第三方包.
	//
	// 其余沙箱硬项 (NoNewPrivileges / ProtectSystem=strict / SystemCallFilter /
	// RestrictAddressFamilies...) 不受本开关影响, 仍然无条件生效.
	AllowDeviceAccess bool

	// BindReadOnlyPaths 把宿主上的路径绑定挂载进 unit 的挂载命名空间 (只读).
	//
	// 存在的直接原因是图形界面: PrivateTmp=true 给组件一个私有 /tmp, 而 X11
	// 客户端要通过 /tmp/.X11-unix/X<n> 这个 unix socket 连显示服务器 -
	// 私有 /tmp 里没有那个目录, 于是任何 GUI 组件都以
	// "Can't connect to X11 window server"启动失败, 报错和沙箱看不出关系.
	//
	// 绑定挂载在 PrivateTmp 之后生效, 所以能把宿主的 X11 socket 目录送回
	// 私有 /tmp 里, 同时保留"组件之间 /tmp 互相隔离"这条性质 -
	// 比直接关掉 PrivateTmp 精确得多.
	//
	// 只读, 且 ignore_enoent: 无头启动 (没有 X 服务器) 时路径不存在,
	// 组件应当照常启动然后自己失败, 而不是连 unit 都拉不起来 -
	// 后者在 systemd 层报错, 排查时根本看不到是哪个组件要图形界面.
	BindReadOnlyPaths []string

	// AmbientCapabilities 是授予该 unit 的 Linux capability 名.
	//
	// 为什么 Ambient 而不是 Bounding: 进程以非 root 的 User= 运行,
	// 普通的 permitted/effective 集在 execve 后会被清空 (非 root 且二进制没有
	// file capability). Ambient 集是唯一能跨 execve 保留, 并在非 root 身份上
	// 生效的途径 - systemd 在降权之前 raise 它们.
	//
	// 同时下发 CapabilityBoundingSet: bounding 集是 ambient 的上界, 不设的话
	// systemd 的缺省 bounding 集可能不含要授予的 cap, ambient raise 会失败,
	// 而 unit 照常启动, 只是没有那个能力 - 症状是运行期 EPERM, 跟没配一样.
	AmbientCapabilities []string

	// ExtraAddressFamilies 是在基线之外额外放行的 socket 地址族.
	//
	// 基线 (AF_UNIX/AF_INET/AF_INET6) 无条件给所有组件, 见 BuildProperties.
	// 蓝牙的 AF_BLUETOOTH, CAN 总线的 AF_CAN 走这里.
	ExtraAddressFamilies []string
}

// UnitSpec 是一次 StartTransientUnit 的完整输入
type UnitSpec struct {
	Name        string   // nervus-<pkgid>-<compid>.service
	Description string   // 人类可读, 仅用于 systemd status 展示
	ExecPath    string   // 绝对路径: native=包内 ELF; jvm=/usr/lib/nervus/jre/bin/java
	Args        []string // ExecStart 参数 (不含 argv[0])
	UID         uint32
	GID         uint32
	WorkingDir  string // /var/lib/nervus/package-data/<id>
	Env         []string
	Limits      Limits
	Sandbox     Sandbox
	// BindToUnit 非空时给瞬态 unit 加 BindsTo/After=<该 unit>: 绑定的 unit 一旦
	// inactive/failed (含 nervud 被 SIGKILL 后 nervud.service 进入 failed), systemd
	// 会连带停掉本 unit, 杜绝nervud 死了, 组件还归 systemd 持有继续跑. 生产设为
	// nervud.service; 测试留空 (避免绑一个不存在的 unit 导致起不来)
	BindToUnit string
}

// property 是 StartTransientUnit 的一条属性 (D-Bus 结构 (sv))
type property struct {
	Name  string
	Value dbus.Variant
}

// execStartItem 对应 ExecStart 的 D-Bus 类型 a(sasb): 路径, argv (含 argv[0]),
// uncleanIsFailure. argv[0] 按惯例填 ExecPath 本身
type execStartItem struct {
	Path             string
	Argv             []string
	UncleanIsFailure bool
}

// restrictSet 对应 SystemCallFilter / RestrictAddressFamilies 的 D-Bus 类型 (bas):
// whitelist 标志 + 名称列表
type restrictSet struct {
	Whitelist bool
	Values    []string
}

// bindPath 对应 BindPaths / BindReadOnlyPaths 的 D-Bus 类型 a(ssbt):
// 源路径, 目标路径, 路径不存在时是否忽略, mount flags.
//
// MountFlags 取 0 (等价 MS_NONE, 非递归). X11 socket 目录下没有嵌套挂载,
// 不需要 MS_REC; 用 0 是最小权限, 避免把宿主上恰好挂在该路径下的东西一并带进去.
type bindPath struct {
	Source       string
	Destination  string
	IgnoreENOENT bool
	MountFlags   uint64
}

// validateSpec 做发起 D-Bus 前的本地白名单校验 (本地白名单校验, 不接受调用方
// 传任意 systemd property). 返回 nil 才允许构造属性
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
// 属性集固定: 调用方只能通过 UnitSpec 的受限字段影响 exec/uid/limits/沙箱
// 路径, 不能注入任意 systemd property. 沙箱硬项 (NoNewPrivileges/ProtectSystem=strict/
// PrivateDevices/...) 无条件加上, 不给放宽入口
func BuildProperties(spec UnitSpec) ([]property, error) {
	if err := validateSpec(spec); err != nil {
		return nil, err
	}

	argv := append([]string{spec.ExecPath}, spec.Args...)
	props := []property{
		{"Description", dbus.MakeVariant(spec.Description)},

		// CollectMode=inactive-or-failed: 进程退出后让 systemd自动回收这个
		// 瞬态 unit, 不留残骸.
		//
		// 没有它, 任何组件崩一次之后就再也起不来. systemd 默认把退出的
		// 瞬态 unit 保留在 inactive/failed 状态; supervisor 按退避重启时用同一个
		// unit 名再调 StartTransientUnit, systemd 直接报
		// "Unit... was already loaded or has a fragment file" 并失败.
		// 于是整套退避重启与熔断机制被彻底废掉 - 第一次崩溃就是最后一次.
		//
		// 这不是理论问题: 端到端验证里 pkgmanagerd 起来两秒后退出, 重启立刻
		// 撞上它.
		//
		// 为什么用 CollectMode 而不是每次 start 前先 ResetFailedUnit:
		// 后者是"先清残骸再启动"的补救, 两步之间有窗口, 而且只覆盖 failed,
		// 覆盖不了正常退出留下的 inactive. CollectMode 让回收成为 unit 自身的
		// 属性, 由 systemd 在它退出那一刻负责.
		{"CollectMode", dbus.MakeVariant("inactive-or-failed")},
		{"ExecStart", dbus.MakeVariant([]execStartItem{{Path: spec.ExecPath, Argv: argv, UncleanIsFailure: false}})},
		// 数字 UID/GID 以字符串形式传给 systemd (User/Group 接受数字字符串)
		{"User", dbus.MakeVariant(fmt.Sprintf("%d", spec.UID))},
		{"Group", dbus.MakeVariant(fmt.Sprintf("%d", spec.GID))},
		{"WorkingDirectory", dbus.MakeVariant(spec.WorkingDir)},

		// ---- 通用沙箱硬项 (无条件) ----
		{"NoNewPrivileges", dbus.MakeVariant(true)},
		{"ProtectSystem", dbus.MakeVariant("strict")},
		{"ProtectHome", dbus.MakeVariant("yes")},
		{"PrivateTmp", dbus.MakeVariant(true)},
		{"ProtectKernelTunables", dbus.MakeVariant(true)},
		{"ProtectKernelModules", dbus.MakeVariant(true)},
		{"RestrictSUIDSGID", dbus.MakeVariant(true)},
		{"RestrictRealtime", dbus.MakeVariant(true)},
		// SystemCallFilter=@system-service (whitelist) 已排除 @mount/@module/@raw-io/
		// @privileged/@debug
		{"SystemCallFilter", dbus.MakeVariant(restrictSet{Whitelist: true, Values: []string{"@system-service"}})},
	}

	// 地址族: 基线 UNIX/INET/INET6 堵住 raw/packet socket 等; 组件可按 manifest
	// 声明追加 (蓝牙的 AF_BLUETOOTH, CAN 的 AF_CAN).
	//
	// 这道墙与 capability 无关: 它在 seccomp 层, socket(AF_BLUETOOTH,...)
	// 不在白名单里就是 EAFNOSUPPORT, 进程即便有 CAP_NET_ADMIN 也一样.
	families := append([]string{"AF_UNIX", "AF_INET", "AF_INET6"}, spec.Sandbox.ExtraAddressFamilies...)
	props = append(props, property{
		"RestrictAddressFamilies",
		dbus.MakeVariant(restrictSet{Whitelist: true, Values: families}),
	})

	// Capability: ambient + bounding 一起下发.
	//
	// 必须是 uint64 位掩码, 不是字符串数组. unit 文件里写
	// "AmbientCapabilities=CAP_NET_ADMIN" 是 systemd 的配置语法糖; 而
	// StartTransientUnit 走的是 D-Bus, 这两个属性的签名是 t (uint64).
	// 发字符串数组 systemd 会以 "Failed to set unit properties: Unexpected
	// message contents" 整体拒绝 - 错误里不会提是哪个属性, 排查时看不出
	// 是类型问题还是值不合法.
	//
	// 只在非空时下发: 空集时保持 systemd 对非 root User= 的缺省行为 (无能力),
	// 显式下发一个 0 掩码反而会写成 unit 属性, 让 systemctl show 的输出与
	// "什么都没配"区分不开.
	if len(spec.Sandbox.AmbientCapabilities) > 0 {
		mask, err := capMask(spec.Sandbox.AmbientCapabilities)
		if err != nil {
			return nil, err
		}
		props = append(props,
			// bounding 必须一并给出: 它是 ambient 的上界, 缺了 ambient raise
			// 会静默失败, unit 照常起来但没有那个能力 - 症状是运行期 EPERM,
			// 跟没配一样
			property{"CapabilityBoundingSet", dbus.MakeVariant(mask)},
			property{"AmbientCapabilities", dbus.MakeVariant(mask)},
		)
	}

	// 设备访问: 默认 (AllowDeviceAccess=false) 保持原来的两条硬项不变;
	// 放开时 PrivateDevices 关闭 + DevicePolicy=auto, 让 Provider 能看到宿主
	// 的 /dev 并按 DAC 权限访问真实设备节点. 两条属性无论哪个分支都显式下发,
	// 不依赖 systemd 的缺省值 - 瞬态 unit 的缺省随版本变化, 写死才可预期.
	if spec.Sandbox.AllowDeviceAccess {
		props = append(props,
			property{"PrivateDevices", dbus.MakeVariant(false)},
			property{"DevicePolicy", dbus.MakeVariant("auto")},
		)
	} else {
		props = append(props,
			property{"PrivateDevices", dbus.MakeVariant(true)},
			property{"DevicePolicy", dbus.MakeVariant("closed")},
		)
	}

	if spec.BindToUnit != "" {
		// BindsTo: 被绑 unit 停/failed 即连带停本 unit (owner-death 语义).
		// After: 确保本 unit 在被绑 unit 之后启动, 绑定关系才有意义
		props = append(props, property{"BindsTo", dbus.MakeVariant([]string{spec.BindToUnit})})
		props = append(props, property{"After", dbus.MakeVariant([]string{spec.BindToUnit})})
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
	if len(spec.Sandbox.BindReadOnlyPaths) > 0 {
		binds := make([]bindPath, 0, len(spec.Sandbox.BindReadOnlyPaths))
		for _, p := range spec.Sandbox.BindReadOnlyPaths {
			// 源与目标同路径: 目的是"把宿主的这个路径原样送进命名空间",
			// 而不是改变它在组件眼里的位置. 换位置只会让组件里的绝对路径
			//  (X11 的 /tmp/.X11-unix 是写死在客户端库里的) 对不上
			binds = append(binds, bindPath{
				Source: p, Destination: p, IgnoreENOENT: true, MountFlags: 0,
			})
		}
		props = append(props, property{"BindReadOnlyPaths", dbus.MakeVariant(binds)})
	}

	// ---- 资源上限 (零值不设) ----
	if spec.Limits.MemoryMaxBytes > 0 {
		props = append(props, property{"MemoryMax", dbus.MakeVariant(spec.Limits.MemoryMaxBytes)})
	}
	if spec.Limits.TasksMax > 0 {
		props = append(props, property{"TasksMax", dbus.MakeVariant(spec.Limits.TasksMax)})
	}
	if spec.Limits.CPUQuotaPercent > 0 {
		// CPUQuotaPerSecUSec: 每秒可用 CPU 微秒数. 100% = 1 秒 = 1_000_000us
		usec := uint64(spec.Limits.CPUQuotaPercent) * 10_000
		props = append(props, property{"CPUQuotaPerSecUSec", dbus.MakeVariant(usec)})
	}

	return props, nil
}

// ---- Capability 名字 -> 位掩码 -------------------------------------------

// ErrUnknownCapability capability 名不认识, 无法翻成位序号
var ErrUnknownCapability = errors.New("systemd: unknown capability name")

// capBits 是 capability 名 -> 位序号. 序号即 linux/capability.h 里的 CAP_*
// 常量值, 与 /proc/<pid>/status 的 CapEff/CapAmb 位掩码一一对应.
//
// 为什么本包要自己存一份而不是从 pkgregistry 拿: systemd 子包不 import
// pkgregistry (那会依赖倒挂, 见 Runtime 枚举同样的处理). 两份表都是对
// capabilities(7) 的抄写, 抄错会被 TestCapMask 逐条比出来.
var capBits = map[string]uint{
	"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2, "CAP_FOWNER": 3,
	"CAP_FSETID": 4, "CAP_KILL": 5, "CAP_SETGID": 6, "CAP_SETUID": 7,
	"CAP_SETPCAP": 8, "CAP_LINUX_IMMUTABLE": 9, "CAP_NET_BIND_SERVICE": 10,
	"CAP_NET_BROADCAST": 11, "CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13,
	"CAP_IPC_LOCK": 14, "CAP_IPC_OWNER": 15, "CAP_SYS_MODULE": 16, "CAP_SYS_RAWIO": 17,
	"CAP_SYS_CHROOT": 18, "CAP_SYS_PTRACE": 19, "CAP_SYS_PACCT": 20, "CAP_SYS_ADMIN": 21,
	"CAP_SYS_BOOT": 22, "CAP_SYS_NICE": 23, "CAP_SYS_RESOURCE": 24, "CAP_SYS_TIME": 25,
	"CAP_SYS_TTY_CONFIG": 26, "CAP_MKNOD": 27, "CAP_LEASE": 28, "CAP_AUDIT_WRITE": 29,
	"CAP_AUDIT_CONTROL": 30, "CAP_SETFCAP": 31, "CAP_MAC_OVERRIDE": 32, "CAP_MAC_ADMIN": 33,
	"CAP_SYSLOG": 34, "CAP_WAKE_ALARM": 35, "CAP_BLOCK_SUSPEND": 36, "CAP_AUDIT_READ": 37,
	"CAP_PERFMON": 38, "CAP_BPF": 39, "CAP_CHECKPOINT_RESTORE": 40,
}

// capMask 把 capability 名字列表翻成 systemd D-Bus 要的 uint64 位掩码.
//
// 不认识的名字整体失败而不是跳过: 跳过的话组件照常起来, 照常缺那个能力,
// 症状是运行期 EPERM, 而日志里没有任何线索说少了一条.
func capMask(names []string) (uint64, error) {
	var mask uint64
	for _, n := range names {
		bit, ok := capBits[n]
		if !ok {
			return 0, fmt.Errorf("%w: %q", ErrUnknownCapability, n)
		}
		mask |= 1 << bit
	}
	return mask, nil
}

// ---- 本地白名单校验 ------------------------------------------------------

// validUnitName 报告 name 是否是安全的瞬态 unit 名: 必须以 nervus- 前缀 +
// .service 后缀, 中间只允许 [a-z0-9._-], 无斜杠, 无路径分隔, 长度有界.
//
// 前缀锁定为 nervus- 是为了让 nervud 起的瞬态 unit 与系统其它 unit 在命名空间上
// 隔离, StopUnit 时也不可能误停一个系统关键 unit
func validUnitName(name string) bool {
	const prefix = "nervus-"
	const suffix = ".service"
	if len(name) < len(prefix)+len(suffix)+1 || len(name) > 255 {
		return false
	}
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	mid := name[:len(name)-len(suffix)] // 去掉.service, 含前缀
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

// isAbsClean 报告 p 是否是一个绝对, 无控制字符的 Linux 路径
func isAbsClean(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") {
		return false
	}
	return !strings.ContainsAny(p, "\x00\n")
}

// validEnvEntry 报告 e 是否是安全的 "KEY=VALUE": 含 '=', 键为 [A-Za-z_][A-Za-z0-9_]*,
// 整条无 NUL/换行 (防注入进 systemd unit)
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
			// ok (首尾均可)
		case j > 0 && c >= '0' && c <= '9':
			// ok (数字不能作首字符)
		default:
			return false
		}
	}
	return true
}
