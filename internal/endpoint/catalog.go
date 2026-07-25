// 本文件是 interface 级权限门槛表：endpoint_id/method_id ->
// permission ID 的映射手段在 v1 的落地形态，只做到 interface 粒度。方法级
// （method_id 级）permission/大小上限的 Method Registry 是随 .proto schema
// 演进的细粒度目录，留待 nervus-ipc 的 schema 工具链落地时接入，不在这里手写
package endpoint

// InterfaceCatalogEntry 是一条已注册 Interface 的 v1 权限声明
type InterfaceCatalogEntry struct {
	InterfaceID string
	// RequiredPermission 为空表示 Resolve 阶段无需额外权限
	// （仍然要满足 manifest exports 声明 + trust，见 RegisterEndpoint）
	RequiredPermission string
}

// InterfaceCatalog 是编译期小表：interface_id -> 权限门槛
//
// 零值 InterfaceCatalog（nil map）fail-safe 视为"没有任何已注册接口"，
// Lookup 一律未命中 - 与 permission.Catalog 对未初始化状态的处理同一思路
type InterfaceCatalog struct {
	entries map[string]InterfaceCatalogEntry
}

// NewInterfaceCatalog 构造一份 InterfaceCatalog
func NewInterfaceCatalog(entries []InterfaceCatalogEntry) InterfaceCatalog {
	m := make(map[string]InterfaceCatalogEntry, len(entries))
	for _, e := range entries {
		m[e.InterfaceID] = e
	}
	return InterfaceCatalog{entries: m}
}

// Lookup 按 interface_id 查权限声明
func (c InterfaceCatalog) Lookup(id string) (InterfaceCatalogEntry, bool) {
	e, ok := c.entries[id]
	return e, ok
}

// DefaultInterfaceCatalog 返回编译期硬编码的最小 interface 目录
//
// 照抄 permission.DefaultCatalog 的自洽性原则 - 不要在没有产品侧输入之前
// 往这里堆更多看起来完备的条目。这里只登记 v1 唯一存在的
// 标准接口，权限 ID 必须与 permission.DefaultCatalog 中登记的一致
func DefaultInterfaceCatalog() InterfaceCatalog {
	return NewInterfaceCatalog([]InterfaceCatalogEntry{
		{InterfaceID: "nervus.interface.motion.base", RequiredPermission: "perm.motion.control"},
		// 内建接口（由 nervud 自己实现，见 endpoint/builtin.go）。
		//
		// 【内建不等于免检】：Resolve 阶段照样查这张表。「谁实现的」与「谁能调」
		// 是两件独立的事——恰恰因为它由内核实现、能直接操作安全状态，
		// 门槛才更该登记在这里。
		//
		// 这里只能挂一个接口级权限。GetState 只需要 observe，而 Rearm 需要
		// rearm —— 两者差着 OEM 与 platform 两个 trust 等级。取更严的那个作为
		// 接口级门槛，method 级细分等 method_registry 接线后由 method_meta 承担
		// （safety_control.proto 里已经逐方法标好了 required_permission）。
		//
		// 取严不取松：让一个只想读状态的包暂时也需要 rearm 权限，代价是它读不到；
		// 反过来取松，一个只该读状态的包就能解开停机锁存。
		{InterfaceID: "nervus.interface.safety.control", RequiredPermission: "perm.safety.rearm"},
		// 装包接口。由 nervus.pkgmanagerd 实现（本仓库之外，见
		// nervus-system-server）。
		//
		// 【漏登记这一条是提权】：下面 Resolve 的 Lookup 未命中时
		// requiredPermission 取空串，即不设门槛——任意 Ordinary 应用都能解析到
		// pkgmanagerd 并让它把任意 .nspkg 装进系统。目录缺条目在这里不是
		// fail-closed 而是 fail-open，凡新增标准接口必须同步登记。
		{InterfaceID: "nervus.interface.pkg.manager", RequiredPermission: "perm.pkg.install"},
		// 机械臂。resource.DefaultRegistry 早就登记了 nervus.resource.manipulator.arm，
		// manipulator.proto 也逐方法标了 required_permission，唯独【这张表】漏了它
		// ——于是 Resolve 走 fail-open 分支，任何 Ordinary 应用都能解析到机械臂
		// 并指挥它运动。
		//
		// 这条与 pkg.manager 那条是同一个教训：资源登记了、proto 标了，都不构成
		// 门槛，Resolve 只看这张表。
		//
		// 取接口级最严：proto 里 GetArmState/SubscribeArmState 没标权限（只读），
		// 但 v1 只能挂一个接口级门槛，与 safety.control 同一取舍——宁可让只想读
		// 状态的包也需要 control 权限，也不能让只该读状态的包能让手臂动起来。
		{InterfaceID: "nervus.interface.manipulator.arm", RequiredPermission: "perm.manipulator.control"},
		// 整机电源（有序重启/关机）。内建接口，由 nervud 自己实现，
		// 见 internal/power/builtin.go。
		//
		// 与 safety.control / pkg.manager 同一个教训：漏登记这一条不是
		// fail-closed 而是 fail-open —— Lookup 未命中时 requiredPermission
		// 取空串，即【不设门槛】，任意 Ordinary 应用都能把机器关掉。
		{InterfaceID: "nervus.interface.power", RequiredPermission: "perm.authority.power"},
	})
}
