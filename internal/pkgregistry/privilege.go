// 本文件是 Component 请求的【Linux 层特权】的白名单：capability 与 socket
// 地址族。
//
// # 为什么要有这两样
//
// 组件以 App UID（20000-59999）运行，非 root，沙箱不给任何 capability。
// 驱动无线电（蓝牙 rfkill、hci up）、配置网络这类操作因此一律 EPERM。
//
// 【不能改成让组件跑 root】：ipc 握手会 CheckUID 拒绝 root 对端
// （internal/ipc/ipc.go），跑 root 的组件根本连不上控制面——它就不再是一个
// Nervus 服务，只是个跑在系统上的普通守护进程。capability 是唯一不破坏
// 身份模型的路。
//
// # 白名单在这里挡的是什么
//
// 【不是策略筛选】——v1 收录 Linux 的全部 capability，系统服务想要哪个填哪个。
// 它挡的是两件更基本的事：
//
//	打字错误  "CAP_NET_ADMN" 会被 systemd 静默忽略，组件照常起来、照常 EPERM，
//	          而日志里没有任何线索。这里直接拒绝装载，错误指到具体那个字符串
//	注入      这两个字段的值原样进 systemd 的 unit 属性，不校验就是让 manifest
//	          往 D-Bus 调用里塞任意字符串
//
// # 真正的约束在别处
//
// 只有【系统镜像来源】的包拿得到这些声明（见 service.buildStartReq）。动态
// 安装的包填了会被忽略——把 capability 交给任意第三方包等于沙箱不存在。
package pkgregistry

import (
	"fmt"
	"slices"
	"strings"
)

// allowedCapabilities 是 Component 可以请求的 capability：Linux 全集。
//
// 按 capabilities(7) 的顺序排，便于与 man page 对照核。
//
// 【标 ⚠ 的几条等价于 root】：拿到其中任何一条的进程都能把自己变成 root，
// 或直接改写内核行为。给出去之前想清楚这个包值不值得——它们不会被这里拒绝，
// 但也不该被当作「一个稍微多一点的权限」。
var allowedCapabilities = map[string]struct{}{
	// ---- 文件与所有权 ----
	"CAP_CHOWN":           {}, // 改任意文件属主
	"CAP_DAC_OVERRIDE":    {}, // ⚠ 绕过一切文件读写权限检查
	"CAP_DAC_READ_SEARCH": {}, // 绕过文件读与目录搜索权限
	"CAP_FOWNER":          {}, // 绕过「必须是属主」的检查
	"CAP_FSETID":          {}, // 改文件时不清 setuid/setgid 位
	"CAP_LINUX_IMMUTABLE": {}, // 设置 immutable / append-only 属性
	"CAP_MKNOD":           {}, // ⚠ 建设备节点——能建一个 /dev/sda 然后直接读裸盘
	"CAP_LEASE":           {}, // 对文件加租约
	"CAP_SETFCAP":         {}, // ⚠ 给文件设 capability，可用于持久化提权

	// ---- 进程与身份 ----
	"CAP_KILL":       {}, // 给任意进程发信号
	"CAP_SETGID":     {}, // ⚠ 变成任意 GID
	"CAP_SETUID":     {}, // ⚠ 变成任意 UID——包括 root
	"CAP_SETPCAP":    {}, // ⚠ 改自己/别人的 capability 集
	"CAP_SYS_PTRACE": {}, // ⚠ ptrace 任意进程——能读走别的包的内存

	// ---- 网络与无线电 ----
	"CAP_NET_ADMIN":        {}, // 网络接口配置、rfkill、hci up/down（蓝牙开关要它）
	"CAP_NET_RAW":          {}, // 原始套接字：HCI raw、ICMP、抓包
	"CAP_NET_BIND_SERVICE": {}, // 绑定 1024 以下端口
	"CAP_NET_BROADCAST":    {}, // 广播与多播

	// ---- IPC ----
	"CAP_IPC_LOCK":  {}, // mlock / mlockall
	"CAP_IPC_OWNER": {}, // 绕过 System V IPC 权限检查

	// ---- 系统 ----
	"CAP_SYS_ADMIN":      {}, // ⚠ 「新的 root」：mount、namespace、quota 及一大批说不清边界的操作
	"CAP_SYS_MODULE":     {}, // ⚠ 装卸内核模块——等于改写内核
	"CAP_SYS_RAWIO":      {}, // ⚠ 直接 I/O 端口与 /dev/mem
	"CAP_SYS_CHROOT":     {}, // chroot
	"CAP_SYS_PACCT":      {}, // 进程记账开关
	"CAP_SYS_BOOT":       {}, // reboot / kexec
	"CAP_SYS_NICE":       {}, // 实时优先级与 nice
	"CAP_SYS_RESOURCE":   {}, // 突破各类资源上限
	"CAP_SYS_TIME":       {}, // 改系统时钟
	"CAP_SYS_TTY_CONFIG": {}, // tty 配置与 vhangup

	// ---- 审计与可观测 ----
	"CAP_AUDIT_WRITE":   {}, // 往审计日志写记录
	"CAP_AUDIT_CONTROL": {}, // ⚠ 改审计规则——能把自己的行为从审计里摘掉
	"CAP_AUDIT_READ":    {}, // 读审计日志
	"CAP_SYSLOG":        {}, // 读内核环形缓冲、控制 dmesg

	// ---- 强制访问控制 ----
	"CAP_MAC_OVERRIDE": {}, // ⚠ 绕过 MAC（SELinux/AppArmor）
	"CAP_MAC_ADMIN":    {}, // ⚠ 改 MAC 策略

	// ---- 电源与新特性 ----
	"CAP_WAKE_ALARM":         {}, // 设置唤醒定时器
	"CAP_BLOCK_SUSPEND":      {}, // 阻止系统挂起
	"CAP_PERFMON":            {}, // 性能监控
	"CAP_BPF":                {}, // ⚠ 装载 BPF 程序
	"CAP_CHECKPOINT_RESTORE": {}, // CRIU 检查点/恢复
}

// allowedAddressFamilies 是 Component 可以额外请求放行的 socket 地址族。
//
// AF_UNIX / AF_INET / AF_INET6 是【所有组件无条件拥有】的基线（见
// systemd.BuildProperties），不在这张表里——把基线也做成可声明的，只会让
// 每个 manifest 都得抄一遍。
//
// 【这道墙与 capability 无关】：RestrictAddressFamilies 是 seccomp 层的，
// 再多 capability 也绕不过去。只给 capability 不给地址族，蓝牙一样打不开，
// 而错误看起来像「协议不支持」（EAFNOSUPPORT），与权限毫无关系。
var allowedAddressFamilies = map[string]struct{}{
	"AF_BLUETOOTH": {}, // 蓝牙：HCI / L2CAP / RFCOMM
	"AF_CAN":       {}, // CAN 总线：机器人执行器的常见通道
	"AF_NETLINK":   {}, // 内核事件与网络配置（rfkill 也走 netlink）
	"AF_PACKET":    {}, // 链路层原始帧
	"AF_ALG":       {}, // 内核加密接口
	"AF_VSOCK":     {}, // 虚拟机 host/guest 通道
	"AF_XDP":       {}, // 高性能收包
}

// EffectiveCapabilities 给出一个 Component 最终生效的 capability 集合。
//
// Privileged 展开成全集；否则就是它自己声明的那些。
//
// 返回排序后的切片而不是 map 序：它会进 systemd 的 unit 属性，也会进审计
// 日志——不稳定的顺序会让两次相同的启动看起来不一样，diff 时全是噪音。
func EffectiveCapabilities(c Component) []string {
	if c.Privileged {
		return sortedKeys(allowedCapabilities)
	}
	if len(c.Capabilities) == 0 {
		return nil
	}
	return append([]string(nil), c.Capabilities...)
}

// EffectiveAddressFamilies 给出一个 Component 最终生效的额外地址族。
//
// 不含 AF_UNIX/AF_INET/AF_INET6——那三个是所有组件的基线，由 systemd 层
// 无条件加上。
func EffectiveAddressFamilies(c Component) []string {
	if c.Privileged {
		return sortedKeys(allowedAddressFamilies)
	}
	if len(c.AddressFamilies) == 0 {
		return nil
	}
	return append([]string(nil), c.AddressFamilies...)
}

func sortedKeys(m map[string]struct{}) []string {
	out := keysOf(m)
	slices.Sort(out)
	return out
}

// validateComponentPrivileges 校验一个 Component 请求的 capability 与地址族。
//
// Privileged 不需要校验：它展开的是本文件里的白名单自身，不可能越界。
func validateComponentPrivileges(c Component) error {
	for _, capName := range c.Capabilities {
		if _, ok := allowedCapabilities[capName]; !ok {
			return fmt.Errorf("%w: component %q requests unknown capability %q",
				ErrInvalidCapability, c.ID, capName)
		}
	}
	for _, af := range c.AddressFamilies {
		if _, ok := allowedAddressFamilies[af]; !ok {
			return fmt.Errorf("%w: component %q requests unknown address family %q",
				ErrInvalidAddressFamily, c.ID, af)
		}
	}
	return nil
}

// KnownCapabilities 返回白名单里的全部 capability，供诊断与文档生成。
// 顺序不保证，调用方要稳定输出请自行排序。
func KnownCapabilities() []string { return keysOf(allowedCapabilities) }

// KnownAddressFamilies 返回白名单里的全部地址族。
func KnownAddressFamilies() []string { return keysOf(allowedAddressFamilies) }

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// DescribePrivileges 给审计用的一行摘要。
func DescribePrivileges(caps, afs []string) string {
	var b strings.Builder
	if len(caps) > 0 {
		b.WriteString("caps=")
		b.WriteString(strings.Join(caps, ","))
	}
	if len(afs) > 0 {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("af=")
		b.WriteString(strings.Join(afs, ","))
	}
	return b.String()
}
