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
	return &Manager{inv: authority.DefaultInvariants(), perms: &fakePermissions{}}
}

// 没注入例外、也没申请共享文档区时，谁都只有自己的数据目录可写。
func TestReadWritePaths_DefaultIsDataDirOnly(t *testing.T) {
	m := newPathsManager()
	got := m.readWritePaths(entryFor("com.example.app"), "/data/com.example.app")
	if !slices.Equal(got, []string{"/data/com.example.app"}) {
		t.Fatalf("readWritePaths = %v, want only the data dir", got)
	}
}

// newStagingManager 造一个已注入 staging 根、并把 perm.pkg.admin 授予 holder 的
// Manager。holder 为空表示谁都没拿到那条权限。
func newStagingManager(holder string) *Manager {
	perms := &fakePermissions{}
	if holder != "" {
		perms.set(holder, PermissionPackageAdmin, true)
	}
	m := &Manager{inv: authority.DefaultInvariants(), perms: perms}
	m.GrantStagingAccess("/var/lib/nervus/staging")
	return m
}

// 持有 perm.pkg.admin 的包拿到 staging 根。
//
// 少了它，装包会在解包那一步以 read-only file system 失败——而属主与权限
// 都是对的，所以第一反应会去查 chown，查不出问题。
func TestReadWritePaths_PermissionHolderGetsStagingRoot(t *testing.T) {
	m := newStagingManager("nervus.pkgmanagerd")

	got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/nervus.pkgmanagerd")
	want := []string{"/data/nervus.pkgmanagerd", "/var/lib/nervus/staging"}
	if !slices.Equal(got, want) {
		t.Fatalf("readWritePaths = %v, want %v", got, want)
	}
}

// 【判据是权限不是包名】：叫 nervus.pkgmanagerd 但没拿到权限，一样没有 staging。
// 这条锁住本次改造——内核不再认识任何具体的 Package ID。
func TestReadWritePaths_PackageNameAloneGrantsNothing(t *testing.T) {
	m := newStagingManager("") // 谁都没授予

	got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/nervus.pkgmanagerd")
	if slices.Contains(got, "/var/lib/nervus/staging") {
		t.Fatalf("包名匹配但无权限，不该拿到 staging: %v", got)
	}
}

// 任意包名只要持有权限就拿得到——与包名无关。
func TestReadWritePaths_AnyPermissionHolderGetsStaging(t *testing.T) {
	m := newStagingManager("com.vendor.installerd")

	got := m.readWritePaths(entryFor("com.vendor.installerd"), "/data/x")
	if !slices.Contains(got, "/var/lib/nervus/staging") {
		t.Fatalf("持有权限的包必须拿到 staging: %v", got)
	}
}

// 例外只给持有者。别的包拿到 staging 写权限等于可以篡改正在安装的包。
func TestReadWritePaths_OtherPackagesDoNotGetStaging(t *testing.T) {
	m := newStagingManager("nervus.pkgmanagerd")

	for _, pkg := range []string{"com.example.app", "nervus.safety.recovery", ""} {
		got := m.readWritePaths(entryFor(pkg), "/data/x")
		if slices.Contains(got, "/var/lib/nervus/staging") {
			t.Errorf("package %q got staging write access: %v", pkg, got)
		}
	}
}

// 没注入根时，即便持有权限也不能给出半个例外。
func TestReadWritePaths_PartialGrantIsNoGrant(t *testing.T) {
	cases := []struct{ holder, root string }{
		{"nervus.pkgmanagerd", ""},
		{"", "/var/lib/nervus/staging"},
	}
	for _, tc := range cases {
		perms := &fakePermissions{}
		if tc.holder != "" {
			perms.set(tc.holder, PermissionPackageAdmin, true)
		}
		m := &Manager{inv: authority.DefaultInvariants(), perms: perms}
		m.GrantStagingAccess(tc.root)
		got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/x")
		if len(got) != 1 {
			t.Errorf("holder=%q root=%q → readWritePaths = %v, want data dir only",
				tc.holder, tc.root, got)
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
	m.perms.(*fakePermissions).set("com.example.files", permStorageUser, true)
	got := m.readWritePaths(entryWithGrants("com.example.files", permStorageUser), "/data/x")

	if !slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("readWritePaths = %v, want it to contain %q", got, m.inv.UserDataRoot)
	}
}

// 没申请的包拿不到。共享文档区是公共地，但不是默认可达的公共地。
func TestReadWritePaths_NoStorageUserNoUserDataRoot(t *testing.T) {
	m := newPathsManager()
	m.perms.(*fakePermissions).set("com.example.app", permStorageUser, true)
	got := m.readWritePaths(entryFor("com.example.app"), "/data/x")

	if slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("没有 %s 的包拿到了共享文档区: %v", permStorageUser, got)
	}
}

// 判据必须是【裁决结果】而不是 manifest 里的申请。
//
// 若这里误看 manifest.Permissions，一个被中央 catalog/信任裁决拒绝的权限仍然
// 能换到目录，等于权限执法被绕过。用一个「申请了但没被授予」的 Entry 把它钉住。
func TestReadWritePaths_UsesGrantedNotRequested(t *testing.T) {
	m := newPathsManager()
	m.perms.(*fakePermissions).set("com.example.sneaky", permStorageUser, true)
	e := entryFor("com.example.sneaky")
	e.Manifest.Permissions = []string{permStorageUser} // 申请了
	e.GrantedPermissions = nil                         // 但没被授予

	got := m.readWritePaths(e, "/data/x")
	if slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("按 manifest 申请而非裁决结果给了共享文档区: %v", got)
	}
}

func TestReadWritePaths_StorageUserRequiresRuntimeConsent(t *testing.T) {
	m := newPathsManager()
	entry := entryWithGrants("com.example.files", permStorageUser)

	got := m.readWritePaths(entry, "/data/x")
	if slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("install-eligible but runtime-denied package got UserDataRoot: %v", got)
	}
}

// UserDataRoot 未配置（零值 Invariants）时不该往列表里塞一个空路径。
// 空字符串进 ReadWritePaths 会让 systemd 的 unit 属性畸形。
func TestReadWritePaths_EmptyUserDataRootIsSkipped(t *testing.T) {
	perms := &fakePermissions{}
	perms.set("com.example.files", permStorageUser, true)
	m := &Manager{inv: &authority.Invariants{}, perms: perms}
	got := m.readWritePaths(entryWithGrants("com.example.files", permStorageUser), "/data/x")

	if slices.Contains(got, "") {
		t.Fatalf("readWritePaths 里出现空路径: %#v", got)
	}
	if len(got) != 1 {
		t.Fatalf("readWritePaths = %v, want data dir only", got)
	}
}
