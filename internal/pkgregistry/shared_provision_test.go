package pkgregistry

import (
	"context"
	"testing"

	"github.com/nervus-os/nervud/internal/authority"
)

const (
	testSharedRuntimeRoot = "/run/nervus/shared"
	testSharedPersistRoot = "/var/lib/nervus/shared"
)

// 启动扫描必须在两个共享根下各建一个属主为该包、模式 0755 的子目录。
//
// 0755 是共享区存在的全部意义：谁都能读、只有属主能写。写成 0700 就退化成
// 第二个私有目录；写成 0777 则任何包都能篡改别人放出来的配置或模型。
func TestProvision_CreatesSharedDirs(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	mod.SetSharedRoots(testSharedRuntimeRoot, testSharedPersistRoot)

	const pkg = "com.example.svc"
	entry := Entry{
		Manifest:           Manifest{PackageID: pkg},
		UID:                20001,
		GrantedPermissions: []string{PermissionStorageShared},
	}
	if err := mod.provisionEntry(context.Background(), entry); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}

	want := map[string]authority.CreateDataDirRequest{
		testSharedRuntimeRoot + "/" + pkg: {
			Path: testSharedRuntimeRoot + "/" + pkg, UID: 20001, GID: 20001, Perm: 0o755,
		},
		testSharedPersistRoot + "/" + pkg: {
			Path: testSharedPersistRoot + "/" + pkg, UID: 20001, GID: 20001, Perm: 0o755,
		},
	}
	seen := make(map[string]bool)
	for _, req := range installer.dataDirs {
		expected, ok := want[req.Path]
		if !ok {
			continue
		}
		seen[req.Path] = true
		if req != expected {
			t.Errorf("共享目录请求 = %+v, want %+v", req, expected)
		}
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("没有创建共享目录 %q（实际请求：%+v）", path, installer.dataDirs)
		}
	}
}

// 私有数据目录仍然是 0700：共享区的引入不能顺手把它放宽。
func TestProvision_PrivateDataDirStaysPrivate(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	mod.SetSharedRoots(testSharedRuntimeRoot, testSharedPersistRoot)

	const pkg = "com.example.svc"
	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{PackageID: pkg}, UID: 20001,
		GrantedPermissions: []string{PermissionStorageShared},
	}); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}

	found := false
	for _, req := range installer.dataDirs {
		if req.Path != mod.dataRoot+"/"+pkg {
			continue
		}
		found = true
		if req.Perm != 0o700 {
			t.Errorf("私有数据目录 perm = %o, want 0700", req.Perm)
		}
	}
	if !found {
		t.Fatalf("没有创建私有数据目录（实际请求：%+v）", installer.dataDirs)
	}
}

// 未配置共享根时一个共享目录都不建——最小装配与测试可以完全不启用共享区。
func TestProvision_NoSharedDirsWhenRootsUnset(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	// 刻意不调 SetSharedRoots

	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{PackageID: "com.example.svc"}, UID: 20001,
		GrantedPermissions: []string{PermissionStorageShared},
	}); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}
	if len(installer.dataDirs) != 1 {
		t.Fatalf("未启用共享区时应当只建私有数据目录，实际：%+v", installer.dataDirs)
	}
}

// 【没申请 perm.storage.shared 的包一个共享目录都不该占】。
//
// 多数服务用不上共享区。给每个包都建等于在 tmpfs 上白占一批 inode，
// 还让目录列表与「谁真的在用」对不上。
func TestProvision_NoSharedDirsWithoutPermission(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	mod.SetSharedRoots(testSharedRuntimeRoot, testSharedPersistRoot)

	// 没有 GrantedPermissions
	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{PackageID: "com.example.svc"}, UID: 20001,
	}); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}
	if len(installer.dataDirs) != 1 {
		t.Fatalf("没申请共享区的包不该建共享目录，实际：%+v", installer.dataDirs)
	}
}

// 判据是【裁决后的 GrantedPermissions】，不是 manifest 里的申请。
// 按申请建目录等于让任何包写一行 manifest 就占一个位置。
func TestProvision_ManifestRequestAloneIsNotEnough(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	mod.SetSharedRoots(testSharedRuntimeRoot, testSharedPersistRoot)

	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{
			PackageID:   "com.example.svc",
			Permissions: []string{PermissionStorageShared}, // 只是申请
		},
		UID: 20001,
		// GrantedPermissions 为空 = 没被授予
	}); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}
	if len(installer.dataDirs) != 1 {
		t.Fatalf("只申请未获授予不该建共享目录，实际：%+v", installer.dataDirs)
	}
}

// 目录已存在是启动扫描的【正常情况】——本函数每次开机对每个包都跑一遍。
// SharedPersistRoot 在磁盘上，第二次开机时子目录必然已存在。
func TestProvision_SharedDirsIdempotent(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	mod.SetSharedRoots(testSharedRuntimeRoot, testSharedPersistRoot)
	installer.dataDirErr = authority.ErrAlreadyExists

	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{PackageID: "com.example.svc"}, UID: 20001,
		GrantedPermissions: []string{PermissionStorageShared},
	}); err != nil {
		t.Fatalf("目录已存在被当成错误: %v", err)
	}
}
