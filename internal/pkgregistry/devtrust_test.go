package pkgregistry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

func writeDevPackageSig(
	t *testing.T, dir, pkg string, role SignerRole, priv ed25519.PrivateKey, embedKey bool,
) []byte {
	t.Helper()
	pkgDir := filepath.Join(dir, pkg)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", pkgDir, err)
	}
	manifestBytes := []byte(`{"package_id":"` + pkg + `"}`)
	pub := priv.Public().(ed25519.PublicKey)
	msg := append(append([]byte{}, manifestSigDomain...), manifestBytes...)
	sig := ed25519.Sign(priv, msg)

	entry := Signature{
		Role: role, Alg: SigAlgEd25519,
		KeyID: keyIDOf(pub),
		Sig:   base64.StdEncoding.EncodeToString(sig),
	}
	if embedKey {
		entry.Key = base64.StdEncoding.EncodeToString(pub)
	}
	data, err := json.Marshal(SignatureBlock{Format: 1, Signatures: []Signature{entry}})
	if err != nil {
		t.Fatalf("marshal sig block: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, SignatureFileName), data, 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	return manifestBytes
}

func TestLoadDevTrustStore_AnchorsEmbeddedPlatformKey(t *testing.T) {
	dir := t.TempDir()
	priv := newDevKey(t)
	manifestBytes := writeDevPackageSig(t, dir, "nervus.pkgmanagerd", RolePlatformRelease, priv, true)

	store, err := LoadDevTrustStore(dir, nil)
	if err != nil {
		t.Fatalf("LoadDevTrustStore: %v", err)
	}

	sigBytes, err := os.ReadFile(filepath.Join(dir, "nervus.pkgmanagerd", SignatureFileName))
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	signers, err := store.VerifySignature(manifestBytes, sigBytes)
	if err != nil {
		t.Fatalf("VerifySignature with dev anchors: %v", err)
	}
	if got := Arbitrate(SourceSystemImage, signers); got != identity.TrustPlatform {
		t.Fatalf("system-image trust = %v, want %v", got, identity.TrustPlatform)
	}
	if !signers.HasPlatform {
		t.Fatal("HasPlatform = false, want true")
	}
}

func TestLoadDevTrustStore_StillRejectsTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	priv := newDevKey(t)
	writeDevPackageSig(t, dir, "nervus.pkgmanagerd", RolePlatformRelease, priv, true)

	store, err := LoadDevTrustStore(dir, nil)
	if err != nil {
		t.Fatalf("LoadDevTrustStore: %v", err)
	}
	sigBytes, err := os.ReadFile(filepath.Join(dir, "nervus.pkgmanagerd", SignatureFileName))
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	if _, err := store.VerifySignature([]byte(`{"package_id":"tampered"}`), sigBytes); err == nil {
		t.Fatal("tampered manifest verified successfully, want failure")
	}
}

func TestLoadDevTrustStore_IgnoresSignatureWithoutEmbeddedKey(t *testing.T) {
	dir := t.TempDir()
	priv := newDevKey(t)
	writeDevPackageSig(t, dir, "nervus.pkgmanagerd", RolePlatformRelease, priv, false)

	if _, err := LoadDevTrustStore(dir, nil); err == nil {
		t.Fatal("LoadDevTrustStore succeeded without embedded keys, want failure")
	}
}

func TestLoadDevTrustStore_SkipsDeveloperRole(t *testing.T) {
	dir := t.TempDir()
	priv := newDevKey(t)
	writeDevPackageSig(t, dir, "com.example.app", RoleDeveloper, priv, true)

	if _, err := LoadDevTrustStore(dir, nil); err == nil {
		t.Fatal("LoadDevTrustStore anchored a developer key, want failure")
	}
}

func TestLoadDevTrustStore_RejectsKeyIDMismatch(t *testing.T) {
	dir := t.TempDir()
	priv := newDevKey(t)
	other := newDevKey(t)
	pkgDir := filepath.Join(dir, "nervus.pkgmanagerd")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	manifestBytes := []byte(`{"package_id":"nervus.pkgmanagerd"}`)
	msg := append(append([]byte{}, manifestSigDomain...), manifestBytes...)
	sig := ed25519.Sign(priv, msg)
	data, err := json.Marshal(SignatureBlock{Format: 1, Signatures: []Signature{{
		Role: RolePlatformRelease, Alg: SigAlgEd25519,

		KeyID: keyIDOf(other.Public().(ed25519.PublicKey)),
		Key:   base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		Sig:   base64.StdEncoding.EncodeToString(sig),
	}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, SignatureFileName), data, 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}

	if _, err := LoadDevTrustStore(dir, nil); err == nil {
		t.Fatal("LoadDevTrustStore anchored a key_id/key mismatch, want failure")
	}
}

func TestLoadDevTrustStore_DynamicInstallStillOrdinary(t *testing.T) {
	dir := t.TempDir()
	priv := newDevKey(t)
	manifestBytes := writeDevPackageSig(t, dir, "nervus.pkgmanagerd", RolePlatformRelease, priv, true)

	store, err := LoadDevTrustStore(dir, nil)
	if err != nil {
		t.Fatalf("LoadDevTrustStore: %v", err)
	}
	sigBytes, err := os.ReadFile(filepath.Join(dir, "nervus.pkgmanagerd", SignatureFileName))
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	signers, err := store.VerifySignature(manifestBytes, sigBytes)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if got := Arbitrate(SourceDynamicInstall, signers); got != identity.TrustOrdinary {
		t.Fatalf("dynamic-install trust = %v, want %v", got, identity.TrustOrdinary)
	}
}
