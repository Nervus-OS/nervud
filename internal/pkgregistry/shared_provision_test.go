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

//

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
			t.Errorf("unexpected package registry result; value = %+v, want %+v", req, expected)
		}
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("unexpected package registry result; value = %q %+v", path, installer.dataDirs)
		}
	}
}

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
			t.Errorf("unexpected package registry result; perm = %o, want 0700", req.Perm)
		}
	}
	if !found {
		t.Fatalf("unexpected package registry result; value = %+v", installer.dataDirs)
	}
}

func TestProvision_NoSharedDirsWhenRootsUnset(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)

	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{PackageID: "com.example.svc"}, UID: 20001,
		GrantedPermissions: []string{PermissionStorageShared},
	}); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}
	if len(installer.dataDirs) != 1 {
		t.Fatalf("unexpected package registry result; value = %+v", installer.dataDirs)
	}
}

//

func TestProvision_NoSharedDirsWithoutPermission(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	mod.SetSharedRoots(testSharedRuntimeRoot, testSharedPersistRoot)

	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{PackageID: "com.example.svc"}, UID: 20001,
	}); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}
	if len(installer.dataDirs) != 1 {
		t.Fatalf("unexpected package registry result; value = %+v", installer.dataDirs)
	}
}

func TestProvision_ManifestRequestAloneIsNotEnough(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	mod.SetSharedRoots(testSharedRuntimeRoot, testSharedPersistRoot)

	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{
			PackageID:   "com.example.svc",
			Permissions: []string{PermissionStorageShared},
		},
		UID: 20001,
	}); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}
	if len(installer.dataDirs) != 1 {
		t.Fatalf("unexpected package registry result; value = %+v", installer.dataDirs)
	}
}

func TestProvision_SharedDirsIdempotent(t *testing.T) {
	mod, installer, _, _, _ := newTestInstallerWithPerm(t)
	mod.SetSharedRoots(testSharedRuntimeRoot, testSharedPersistRoot)
	installer.dataDirErr = authority.ErrAlreadyExists

	if err := mod.provisionEntry(context.Background(), Entry{
		Manifest: Manifest{PackageID: "com.example.svc"}, UID: 20001,
		GrantedPermissions: []string{PermissionStorageShared},
	}); err != nil {
		t.Fatalf("unexpected package registry result; value = %v", err)
	}
}
