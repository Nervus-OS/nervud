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

//

func newPathsManager() *Manager {
	return &Manager{inv: authority.DefaultInvariants(), perms: &fakePermissions{}}
}

func TestReadWritePaths_DefaultIsDataDirOnly(t *testing.T) {
	m := newPathsManager()
	got := m.readWritePaths(entryFor("com.example.app"), "/data/com.example.app")
	if !slices.Equal(got, []string{"/data/com.example.app"}) {
		t.Fatalf("readWritePaths = %v, want only the data dir", got)
	}
}

func newStagingManager(holder string) *Manager {
	perms := &fakePermissions{}
	if holder != "" {
		perms.set(holder, PermissionPackageAdmin, true)
	}
	m := &Manager{inv: authority.DefaultInvariants(), perms: perms}
	m.GrantStagingAccess("/var/lib/nervus/staging")
	return m
}

//

func TestReadWritePaths_PermissionHolderGetsStagingRoot(t *testing.T) {
	m := newStagingManager("nervus.pkgmanagerd")

	got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/nervus.pkgmanagerd")
	want := []string{"/data/nervus.pkgmanagerd", "/var/lib/nervus/staging"}
	if !slices.Equal(got, want) {
		t.Fatalf("readWritePaths = %v, want %v", got, want)
	}
}

func TestReadWritePaths_PackageNameAloneGrantsNothing(t *testing.T) {
	m := newStagingManager("")

	got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/nervus.pkgmanagerd")
	if slices.Contains(got, "/var/lib/nervus/staging") {
		t.Fatalf("unexpected service result; staging: %v", got)
	}
}

func TestReadWritePaths_AnyPermissionHolderGetsStaging(t *testing.T) {
	m := newStagingManager("com.vendor.installerd")

	got := m.readWritePaths(entryFor("com.vendor.installerd"), "/data/x")
	if !slices.Contains(got, "/var/lib/nervus/staging") {
		t.Fatalf("unexpected service result; staging: %v", got)
	}
}

func TestReadWritePaths_OtherPackagesDoNotGetStaging(t *testing.T) {
	m := newStagingManager("nervus.pkgmanagerd")

	for _, pkg := range []string{"com.example.app", "nervus.safety.recovery", ""} {
		got := m.readWritePaths(entryFor(pkg), "/data/x")
		if slices.Contains(got, "/var/lib/nervus/staging") {
			t.Errorf("package %q got staging write access: %v", pkg, got)
		}
	}
}

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
			t.Errorf("unexpected service result; holder=%q root=%q readWritePaths = %v, want data dir only",
				tc.holder, tc.root, got)
		}
	}
}

func entryWithGrants(pkgID string, granted ...string) pkgregistry.Entry {
	e := entryFor(pkgID)
	e.GrantedPermissions = granted
	return e
}

func TestReadWritePaths_StorageUserGetsUserDataRoot(t *testing.T) {
	m := newPathsManager()
	m.perms.(*fakePermissions).set("com.example.files", permStorageUser, true)
	got := m.readWritePaths(entryWithGrants("com.example.files", permStorageUser), "/data/x")

	if !slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("readWritePaths = %v, want it to contain %q", got, m.inv.UserDataRoot)
	}
}

func TestReadWritePaths_NoStorageUserNoUserDataRoot(t *testing.T) {
	m := newPathsManager()
	m.perms.(*fakePermissions).set("com.example.app", permStorageUser, true)
	got := m.readWritePaths(entryFor("com.example.app"), "/data/x")

	if slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("unexpected service result; value = %s: %v", permStorageUser, got)
	}
}

//

func TestReadWritePaths_UsesGrantedNotRequested(t *testing.T) {
	m := newPathsManager()
	m.perms.(*fakePermissions).set("com.example.sneaky", permStorageUser, true)
	e := entryFor("com.example.sneaky")
	e.Manifest.Permissions = []string{permStorageUser}
	e.GrantedPermissions = nil

	got := m.readWritePaths(e, "/data/x")
	if slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("unexpected service result; manifest: %v", got)
	}
}

// 挂载门只看安装资格, 不看用户此刻同不同意.
//
// 这两道门被刻意分到不同的时间尺度上: 挂载在 spawn 时定死, 改它必须重启进程;
// 而"用户同不同意"要能随时翻转, 于是交给目录上的 ACL - 它在 open(2) 时求值,
// 增删对已经在跑的进程立即生效. 详见 supervise.readWritePaths 与
// ProjectRuntimePermission.
//
// 因此这里断言的是: 运行期未同意【不】阻止目录被挂进来. 真正挡住写的是
// preflight 把该目录设成 01770 之后, ACL 里没有这个 UID 的条目
func TestReadWritePaths_StorageUserIgnoresRuntimeConsent(t *testing.T) {
	m := newPathsManager()
	entry := entryWithGrants("com.example.files", permStorageUser)

	// perms 里没有 set 过, 即运行期未同意
	got := m.readWritePaths(entry, "/data/x")
	if !slices.Contains(got, m.inv.UserDataRoot) {
		t.Fatalf("挂载门不该看运行期同意状态, 但 UserDataRoot 没进来: %v", got)
	}
}

func TestReadWritePaths_EmptyUserDataRootIsSkipped(t *testing.T) {
	perms := &fakePermissions{}
	perms.set("com.example.files", permStorageUser, true)
	m := &Manager{inv: &authority.Invariants{}, perms: perms}
	got := m.readWritePaths(entryWithGrants("com.example.files", permStorageUser), "/data/x")

	if slices.Contains(got, "") {
		t.Fatalf("unexpected service result; readWritePaths: %#v", got)
	}
	if len(got) != 1 {
		t.Fatalf("readWritePaths = %v, want data dir only", got)
	}
}
