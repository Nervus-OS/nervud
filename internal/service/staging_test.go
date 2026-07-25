package service

import (
	"slices"
	"testing"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

func entryFor(pkgID string) pkgregistry.Entry {
	return pkgregistry.Entry{Manifest: pkgregistry.Manifest{PackageID: pkgID}}
}

// newPathsManager 造一个只够 readWritePaths 用的 Manager。
//
// 不能用 &Manager{}：readWritePaths 要读 m.inv.UserDataRoot，inv 为 nil 时空指针。
func newPathsManager() *Manager {
	return &Manager{inv: authority.DefaultInvariants()}
}

// 没注入例外、也没申请共享文档区时，谁都只有自己的数据目录可写。
func TestReadWritePaths_DefaultIsDataDirOnly(t *testing.T) {
	m := newPathsManager()
	got := m.readWritePaths(entryFor("com.example.app"), "/data/com.example.app")
	if !slices.Equal(got, []string{"/data/com.example.app"}) {
		t.Fatalf("readWritePaths = %v, want only the data dir", got)
	}
}

// 装包服务拿到 staging 根。
//
// 少了它，装包会在解包那一步以 read-only file system 失败——而属主与权限
// 都是对的，所以第一反应会去查 chown，查不出问题。
func TestReadWritePaths_StagingPackageGetsStagingRoot(t *testing.T) {
	m := newPathsManager()
	m.GrantStagingAccess("nervus.pkgmanagerd", "/var/lib/nervus/staging")

	got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/nervus.pkgmanagerd")
	want := []string{"/data/nervus.pkgmanagerd", "/var/lib/nervus/staging"}
	if !slices.Equal(got, want) {
		t.Fatalf("readWritePaths = %v, want %v", got, want)
	}
}

// 例外【只给】那一个包。别的包拿到 staging 写权限等于可以篡改正在安装的包。
func TestReadWritePaths_OtherPackagesDoNotGetStaging(t *testing.T) {
	m := newPathsManager()
	m.GrantStagingAccess("nervus.pkgmanagerd", "/var/lib/nervus/staging")

	for _, pkg := range []string{"com.example.app", "nervus.safety.recovery", ""} {
		got := m.readWritePaths(entryFor(pkg), "/data/x")
		if slices.Contains(got, "/var/lib/nervus/staging") {
			t.Errorf("package %q got staging write access: %v", pkg, got)
		}
	}
}

// 只注入了包名没注入根（或反之）时不能给出半个例外。
func TestReadWritePaths_PartialGrantIsNoGrant(t *testing.T) {
	cases := []struct{ pkg, root string }{
		{"nervus.pkgmanagerd", ""},
		{"", "/var/lib/nervus/staging"},
	}
	for _, tc := range cases {
		m := newPathsManager()
		m.GrantStagingAccess(tc.pkg, tc.root)
		got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/x")
		if len(got) != 1 {
			t.Errorf("GrantStagingAccess(%q, %q) → readWritePaths = %v, want data dir only",
				tc.pkg, tc.root, got)
		}
	}
}

// entryWithGrants 造一个带已裁决权限的 Entry。
func entryWithGrants(pkgID string, granted ...string) pkgregistry.Entry {
	e := entryFor(pkgID)
	e.GrantedPermissions = granted
	return e
}

// 申请了共享文档区的包拿得到它。
func TestReadWritePaths_StorageUserGetsUserDataRoot(t *testing.T) {
	m := newPathsManager()
	got := m.readWritePaths(entryWithGrants("com.example.files", permStorageUser), "/data/x")

	if !slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("readWritePaths = %v, want it to contain %q", got, m.inv.UserDataRoot)
	}
}

// 没申请的包拿不到。共享文档区是公共地，但不是默认可达的公共地。
func TestReadWritePaths_NoStorageUserNoUserDataRoot(t *testing.T) {
	m := newPathsManager()
	got := m.readWritePaths(entryFor("com.example.app"), "/data/x")

	if slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("没有 %s 的包拿到了共享文档区: %v", permStorageUser, got)
	}
}

// 判据必须是【裁决结果】而不是 manifest 里的申请。
//
// 现在 permission.V1GrantAll 打开，两者内容一致，这条测不出差别——但执法恢复后
// 就会分叉。那时若还看 manifest.Permissions，一个被拒的权限仍然能换到目录，
// 等于权限执法在这里被绕过。用一个「申请了但没被授予」的 Entry 把它钉住。
func TestReadWritePaths_UsesGrantedNotRequested(t *testing.T) {
	m := newPathsManager()
	e := entryFor("com.example.sneaky")
	e.Manifest.Permissions = []string{permStorageUser} // 申请了
	e.GrantedPermissions = nil                         // 但没被授予

	got := m.readWritePaths(e, "/data/x")
	if slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("按 manifest 申请而非裁决结果给了共享文档区: %v", got)
	}
}

// UserDataRoot 未配置（零值 Invariants）时不该往列表里塞一个空路径。
// 空字符串进 ReadWritePaths 会让 systemd 的 unit 属性畸形。
func TestReadWritePaths_EmptyUserDataRootIsSkipped(t *testing.T) {
	m := &Manager{inv: &authority.Invariants{}}
	got := m.readWritePaths(entryWithGrants("com.example.files", permStorageUser), "/data/x")

	if slices.Contains(got, "") {
		t.Fatalf("readWritePaths 里出现空路径: %#v", got)
	}
	if len(got) != 1 {
		t.Fatalf("readWritePaths = %v, want data dir only", got)
	}
}
