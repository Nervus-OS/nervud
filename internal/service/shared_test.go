package service

import (
	"slices"
	"testing"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

const (
	sharedRuntimeRoot = "/run/nervus/shared"
	sharedPersistRoot = "/var/lib/nervus/shared"
)

// newSharedManager 造一个启用了共享区的 Manager，并按需给包授予 perm.storage.shared。
func newSharedManager(holder string) *Manager {
	inv := authority.DefaultInvariants()
	perms := &fakePermissions{}
	if holder != "" {
		perms.set(holder, permStorageShared, true)
	}
	return &Manager{inv: inv, perms: perms}
}

// entryWithSharedGrant 造一个已被授予 perm.storage.shared 的 Entry。
// 判据同时看 GrantedPermissions（安装资格）与运行期 Allowed，两者都要有。
func entryWithSharedGrant(pkgID string) pkgregistry.Entry {
	return entryWithGrants(pkgID, permStorageShared)
}

// 持有 perm.storage.shared 的包拿到【自己那两个子目录】可写。
func TestReadWritePaths_SharedDirsForPermissionHolder(t *testing.T) {
	const pkg = "com.example.svc"
	m := newSharedManager(pkg)

	got := m.readWritePaths(entryWithSharedGrant(pkg), "/data/"+pkg)
	for _, want := range []string{
		sharedRuntimeRoot + "/" + pkg,
		sharedPersistRoot + "/" + pkg,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("缺少共享子目录 %q: %v", want, got)
		}
	}
}

// 【给的必须是子目录，不是根】。根可写等于允许任意包在根下造目录，
// 那就绕开了「一个包一个目录、属主即写权」这条结构。
func TestReadWritePaths_SharedRootsAreNeverWritable(t *testing.T) {
	const pkg = "com.example.svc"
	m := newSharedManager(pkg)

	got := m.readWritePaths(entryWithSharedGrant(pkg), "/data/"+pkg)
	for _, forbidden := range []string{sharedRuntimeRoot, sharedPersistRoot} {
		if slices.Contains(got, forbidden) {
			t.Errorf("共享区根 %q 不该可写: %v", forbidden, got)
		}
	}
}

// 没有权限就没有共享目录——即便目录在磁盘上已经建好了。
func TestReadWritePaths_NoSharedDirsWithoutPermission(t *testing.T) {
	const pkg = "com.example.svc"
	m := newSharedManager("") // 谁都没授予

	got := m.readWritePaths(entryWithSharedGrant(pkg), "/data/"+pkg)
	for _, forbidden := range []string{
		sharedRuntimeRoot + "/" + pkg,
		sharedPersistRoot + "/" + pkg,
	} {
		if slices.Contains(got, forbidden) {
			t.Errorf("无运行期授予却拿到 %q: %v", forbidden, got)
		}
	}
}

// 只有运行期 Allowed 而没有安装资格（GrantedPermissions）同样不给。
// 两层判据缺一不可，与 perm.storage.user 同规。
func TestReadWritePaths_SharedNeedsInstallEligibilityToo(t *testing.T) {
	const pkg = "com.example.svc"
	m := newSharedManager(pkg)

	// entryFor 不带 GrantedPermissions
	got := m.readWritePaths(entryFor(pkg), "/data/"+pkg)
	if slices.Contains(got, sharedRuntimeRoot+"/"+pkg) {
		t.Errorf("缺安装资格却拿到共享目录: %v", got)
	}
}

// 一个包拿不到【别人】的共享子目录写权限。
func TestReadWritePaths_SharedDirsAreOwnPackageOnly(t *testing.T) {
	const mine, theirs = "com.example.svc", "com.other.svc"
	m := newSharedManager(mine)

	got := m.readWritePaths(entryWithSharedGrant(mine), "/data/"+mine)
	if slices.Contains(got, sharedRuntimeRoot+"/"+theirs) {
		t.Errorf("拿到了别人的共享目录: %v", got)
	}
}

// 未配置共享根时不给出半个例外（与 staging 同规）。
func TestReadWritePaths_SharedDisabledWhenRootsUnset(t *testing.T) {
	const pkg = "com.example.svc"
	perms := &fakePermissions{}
	perms.set(pkg, permStorageShared, true)
	m := &Manager{
		inv:   &authority.Invariants{DataRoot: "/data"}, // 两个共享根都为空
		perms: perms,
	}

	got := m.readWritePaths(entryWithSharedGrant(pkg), "/data/"+pkg)
	if len(got) != 1 {
		t.Fatalf("未配置共享根时应当只有数据目录: %v", got)
	}
}
