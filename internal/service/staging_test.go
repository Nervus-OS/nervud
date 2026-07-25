package service

import (
	"slices"
	"testing"

	"github.com/nervus-os/nervud/internal/pkgregistry"
)

func entryFor(pkgID string) pkgregistry.Entry {
	return pkgregistry.Entry{Manifest: pkgregistry.Manifest{PackageID: pkgID}}
}

// 没注入例外时，谁都只有自己的数据目录可写。
func TestReadWritePaths_DefaultIsDataDirOnly(t *testing.T) {
	m := &Manager{}
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
	m := &Manager{}
	m.GrantStagingAccess("nervus.pkgmanagerd", "/var/lib/nervus/staging")

	got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/nervus.pkgmanagerd")
	want := []string{"/data/nervus.pkgmanagerd", "/var/lib/nervus/staging"}
	if !slices.Equal(got, want) {
		t.Fatalf("readWritePaths = %v, want %v", got, want)
	}
}

// 例外【只给】那一个包。别的包拿到 staging 写权限等于可以篡改正在安装的包。
func TestReadWritePaths_OtherPackagesDoNotGetStaging(t *testing.T) {
	m := &Manager{}
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
		m := &Manager{}
		m.GrantStagingAccess(tc.pkg, tc.root)
		got := m.readWritePaths(entryFor("nervus.pkgmanagerd"), "/data/x")
		if len(got) != 1 {
			t.Errorf("GrantStagingAccess(%q, %q) → readWritePaths = %v, want data dir only",
				tc.pkg, tc.root, got)
		}
	}
}
