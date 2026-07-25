package endpoint

import (
	"strings"
	"testing"

	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/resource"
)

// 接口目录里引用的每个权限 ID 都必须在 permission 目录里真实存在。
//
// 写错一个字在两处都不会报错：permission.Registry 查不到就当没授予，
// endpoint 于是永远拒绝解析这个接口。表现是「服务注册成功了但谁也调不到」，
// 而日志只会说 PERMISSION_DENIED —— 看不出是打错字还是真没权限。
func TestDefaultInterfaceCatalog_PermissionsExist(t *testing.T) {
	perms := permission.DefaultCatalog()
	for id, entry := range DefaultInterfaceCatalog().entries {
		if entry.RequiredPermission == "" {
			continue // 显式无门槛
		}
		if _, ok := perms.Lookup(entry.RequiredPermission); !ok {
			t.Errorf("interface %q requires permission %q, which is not in permission.DefaultCatalog",
				id, entry.RequiredPermission)
		}
	}
}

// 每一个已登记的【物理资源】都必须有一个设了门槛的接口。
//
// 这是唯一一条能自动抓到「接口漏登记」的结构不变量。漏登记在 Resolve 那里是
// fail-open（requiredPermission 取空串，见 resolve.go），没有任何运行期症状——
// nervus.interface.manipulator.arm 就这么一直不设防：resource 表登记了机械臂、
// manipulator.proto 逐方法标了 required_permission，唯独接口目录漏了它，于是
// 任何 Ordinary 应用都能解析到机械臂并指挥它运动。
//
// 命名约定是 nervus.resource.X ↔ nervus.interface.X。新增一款硬件时，
// 只在 resource 表里加而忘了这张表，本用例会立刻失败。
func TestDefaultInterfaceCatalog_CoversEveryResource(t *testing.T) {
	cat := DefaultInterfaceCatalog()
	for _, r := range resource.DefaultRegistry().Entries() {
		ifaceID := strings.Replace(r.Type, "nervus.resource.", "nervus.interface.", 1)
		entry, ok := cat.Lookup(ifaceID)
		if !ok {
			t.Errorf("resource %q 已登记，但接口 %q 不在门槛表里 —— Resolve 会 fail-open，"+
				"任何包都能解析到这个硬件", r.Type, ifaceID)
			continue
		}
		if entry.RequiredPermission == "" {
			t.Errorf("接口 %q（资源 %q）在表里但没有权限门槛", ifaceID, r.Type)
		}
	}
}

// 装包接口必须有门槛。
//
// 单拎出来断言是因为漏掉它的后果与别的接口不同：Resolve 在目录未命中时
// requiredPermission 取空串（见 resolve.go），也就是 fail-open。装包能往
// 系统里放任意可执行文件，无门槛等于任意应用可提权。
func TestDefaultInterfaceCatalog_PkgManagerIsGated(t *testing.T) {
	entry, ok := DefaultInterfaceCatalog().Lookup("nervus.interface.pkg.manager")
	if !ok {
		t.Fatal("nervus.interface.pkg.manager missing from the catalog; Resolve would fail open")
	}
	if entry.RequiredPermission == "" {
		t.Fatal("nervus.interface.pkg.manager has no required permission; any package could install software")
	}
}
