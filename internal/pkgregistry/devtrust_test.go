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

// writeDevPackageSig 在 dir/<pkg>/manifest.sig 写一个 role 角色的签名块，
// 并返回被签名的 manifest 原始字节。
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

// 开发锚点建立之后，同一份 manifest.sig 必须能通过完整的 VerifySignature，
// 并被 Arbitrate 判成 Platform。这是本 flag 存在的全部目的。
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

// 篡改 manifest 之后验签必须照样失败：dev 锚点放松的是「密钥是否被平台根授权」，
// 不是签名本身。这条断言防止本文件被改成「开发期一律放行」。
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

// 没有内嵌公钥就锚不出任何东西：key_id 单独出现不构成身份证明。
func TestLoadDevTrustStore_IgnoresSignatureWithoutEmbeddedKey(t *testing.T) {
	dir := t.TempDir()
	priv := newDevKey(t)
	writeDevPackageSig(t, dir, "nervus.pkgmanagerd", RolePlatformRelease, priv, false)

	if _, err := LoadDevTrustStore(dir, nil); err == nil {
		t.Fatal("LoadDevTrustStore succeeded without embedded keys, want failure")
	}
}

// developer 角色自锚定，不该进入 store —— 它的公钥本来就内嵌在签名块里，
// 由 VerifySignature 自行处理。放进来会模糊「谁需要被授权」这条线。
func TestLoadDevTrustStore_SkipsDeveloperRole(t *testing.T) {
	dir := t.TempDir()
	priv := newDevKey(t)
	writeDevPackageSig(t, dir, "com.example.app", RoleDeveloper, priv, true)

	if _, err := LoadDevTrustStore(dir, nil); err == nil {
		t.Fatal("LoadDevTrustStore anchored a developer key, want failure")
	}
}

// key_id 与内嵌公钥对不上时必须丢弃：否则一个包能用自己的密钥去占用
// 另一个 key_id 的授权位。
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
		// key_id 取另一把钥匙的，内嵌公钥取本把的
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

// 动态安装包即便签了 platform-release，也只能拿 Ordinary。dev 锚点不改变
// 这条来源求交规则 —— 确认开发开关没有把权力泄漏到动态安装路径。
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
