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

func newSharedManager(holder string) *Manager {
	inv := authority.DefaultInvariants()
	perms := &fakePermissions{}
	if holder != "" {
		perms.set(holder, permStorageShared, true)
	}
	return &Manager{inv: inv, perms: perms}
}

func entryWithSharedGrant(pkgID string) pkgregistry.Entry {
	return entryWithGrants(pkgID, permStorageShared)
}

func TestReadWritePaths_SharedDirsForPermissionHolder(t *testing.T) {
	const pkg = "com.example.svc"
	m := newSharedManager(pkg)

	got := m.readWritePaths(entryWithSharedGrant(pkg), "/data/"+pkg)
	for _, want := range []string{
		sharedRuntimeRoot + "/" + pkg,
		sharedPersistRoot + "/" + pkg,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("unexpected service result; value = %q: %v", want, got)
		}
	}
}

func TestReadWritePaths_SharedRootsAreNeverWritable(t *testing.T) {
	const pkg = "com.example.svc"
	m := newSharedManager(pkg)

	got := m.readWritePaths(entryWithSharedGrant(pkg), "/data/"+pkg)
	for _, forbidden := range []string{sharedRuntimeRoot, sharedPersistRoot} {
		if slices.Contains(got, forbidden) {
			t.Errorf("unexpected service result; value = %q: %v", forbidden, got)
		}
	}
}

func TestReadWritePaths_NoSharedDirsWithoutPermission(t *testing.T) {
	const pkg = "com.example.svc"
	m := newSharedManager("")

	got := m.readWritePaths(entryWithSharedGrant(pkg), "/data/"+pkg)
	for _, forbidden := range []string{
		sharedRuntimeRoot + "/" + pkg,
		sharedPersistRoot + "/" + pkg,
	} {
		if slices.Contains(got, forbidden) {
			t.Errorf("unexpected service result; value = %q: %v", forbidden, got)
		}
	}
}

func TestReadWritePaths_SharedNeedsInstallEligibilityToo(t *testing.T) {
	const pkg = "com.example.svc"
	m := newSharedManager(pkg)

	got := m.readWritePaths(entryFor(pkg), "/data/"+pkg)
	if slices.Contains(got, sharedRuntimeRoot+"/"+pkg) {
		t.Errorf("unexpected service result; value = %v", got)
	}
}

func TestReadWritePaths_SharedDirsAreOwnPackageOnly(t *testing.T) {
	const mine, theirs = "com.example.svc", "com.other.svc"
	m := newSharedManager(mine)

	got := m.readWritePaths(entryWithSharedGrant(mine), "/data/"+mine)
	if slices.Contains(got, sharedRuntimeRoot+"/"+theirs) {
		t.Errorf("unexpected service result; value = %v", got)
	}
}

func TestReadWritePaths_SharedDisabledWhenRootsUnset(t *testing.T) {
	const pkg = "com.example.svc"
	perms := &fakePermissions{}
	perms.set(pkg, permStorageShared, true)
	m := &Manager{
		inv:   &authority.Invariants{DataRoot: "/data"},
		perms: perms,
	}

	got := m.readWritePaths(entryWithSharedGrant(pkg), "/data/"+pkg)
	if len(got) != 1 {
		t.Fatalf("unexpected service result; value = %v", got)
	}
}
