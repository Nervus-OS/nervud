package endpoint

import (
	"testing"

	"github.com/nervus-os/nervud/internal/permission"
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
