package pkgregistry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
)

func installRevocationFixture(
	t *testing.T,
	mod *Module,
	key ed25519.PrivateKey,
	version string,
	versionCode uint64,
) error {
	t.Helper()
	staging, manifest, signature := newValidStagingWithKey(
		t, t.TempDir(), "com.example.app", version, versionCode, key,
	)
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifest,
		SigBlock:      signature,
		StagingDir:    staging,
		Source:        SourceDynamicInstall,
	})
	return err
}

func requireSingleTransferRevocation(t *testing.T, revoker *fakeTransferRevoker) {
	t.Helper()
	if len(revoker.packages) != 1 || revoker.packages[0] != "com.example.app" {
		t.Fatalf("transfer revocations = %v, want exactly [com.example.app]", revoker.packages)
	}
}

func TestInstall_FreshInstallDoesNotRevokeTransfers(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	revoker := &fakeTransferRevoker{}
	mod.SetTransferRevoker(revoker)

	if err := installRevocationFixture(t, mod, newDevKey(t), "1.0.0", 100); err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	if len(revoker.packages) != 0 {
		t.Fatalf("fresh install revoked transfers: %v", revoker.packages)
	}
}

func TestInstall_UpgradeRevokesTransfersExactlyOnce(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	revoker := &fakeTransferRevoker{}
	mod.SetTransferRevoker(revoker)
	key := newDevKey(t)

	if err := installRevocationFixture(t, mod, key, "1.0.0", 100); err != nil {
		t.Fatalf("install v1: %v", err)
	}
	if err := installRevocationFixture(t, mod, key, "2.0.0", 200); err != nil {
		t.Fatalf("upgrade v2: %v", err)
	}
	requireSingleTransferRevocation(t, revoker)
}

func TestInstall_SameVersionReplacementRevokesTransfersExactlyOnce(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	revoker := &fakeTransferRevoker{}
	mod.SetTransferRevoker(revoker)
	key := newDevKey(t)

	if err := installRevocationFixture(t, mod, key, "1.0.0", 100); err != nil {
		t.Fatalf("install v1: %v", err)
	}
	if err := installRevocationFixture(t, mod, key, "1.0.0", 100); err != nil {
		t.Fatalf("replace v1: %v", err)
	}
	requireSingleTransferRevocation(t, revoker)
}

func TestInstall_FailureBeforeCommitDoesNotRevokeTransfers(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	revoker := &fakeTransferRevoker{}
	mod.SetTransferRevoker(revoker)
	key := newDevKey(t)

	if err := installRevocationFixture(t, mod, key, "1.0.0", 100); err != nil {
		t.Fatalf("install v1: %v", err)
	}
	wantErr := errors.New("ensure app user failed")
	auth.appUserErr = wantErr
	if err := installRevocationFixture(t, mod, key, "2.0.0", 200); !errors.Is(err, wantErr) {
		t.Fatalf("failed upgrade error = %v, want %v", err, wantErr)
	}
	if len(revoker.packages) != 0 {
		t.Fatalf("failed upgrade revoked transfers: %v", revoker.packages)
	}
}
