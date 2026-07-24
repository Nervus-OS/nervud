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
	})
}
