package pkgregistry

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

//
//

type lineageChain struct {
	keys []ed25519.PrivateKey
}

func newLineage(t *testing.T, n int) lineageChain {
	t.Helper()
	keys := make([]ed25519.PrivateKey, n)
	for i := range keys {
		keys[i] = newDevKey(t)
	}
	return lineageChain{keys: keys}
}

func (lc lineageChain) extend(t *testing.T) lineageChain {
	t.Helper()
	next := make([]ed25519.PrivateKey, len(lc.keys)+1)
	copy(next, lc.keys)
	next[len(lc.keys)] = newDevKey(t)
	return lineageChain{keys: next}
}

func (lc lineageChain) buildLineage(t *testing.T) *Lineage {
	t.Helper()
	if len(lc.keys) <= 1 {
		return nil
	}
	nodes := make([]LineageNode, len(lc.keys))
	for i, k := range lc.keys {
		pub := k.Public().(ed25519.PublicKey)
		nodes[i] = LineageNode{KeyID: keyIDOf(pub), Key: base64.StdEncoding.EncodeToString(pub)}
		if i > 0 {
			prev := lc.keys[i-1]
			msg := append(append(append([]byte{}, lineageSigDomain...), []byte(nodes[i].KeyID)...), pub...)
			nodes[i].SignedByPrev = base64.StdEncoding.EncodeToString(ed25519.Sign(prev, msg))
		}
	}
	return &Lineage{Format: lineageFormatV1, Nodes: nodes}
}

func (lc lineageChain) signWithLineage(t *testing.T, manifestBytes []byte) []byte {
	t.Helper()
	lin := lc.buildLineage(t)
	cur := lc.keys[len(lc.keys)-1]
	pub := cur.Public().(ed25519.PublicKey)

	devMsg := developerSignMessage(manifestBytes, lin)
	sb := SignatureBlock{
		Format: sigBlockFormatV1,
		Signatures: []Signature{{
			Role: RoleDeveloper, Alg: SigAlgEd25519,
			KeyID: keyIDOf(pub),
			Key:   base64.StdEncoding.EncodeToString(pub),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(cur, devMsg)),
		}},
		Lineage: lin,
	}
	data, err := json.Marshal(sb)
	if err != nil {
		t.Fatalf("marshal sig block: %v", err)
	}
	return data
}

func stagingForVersion(t *testing.T, root, packageID, version string, versionCode uint64) (string, []byte) {
	t.Helper()
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	content := "#!/bin/true"
	if err := os.WriteFile(filepath.Join(staging, "bin"), []byte(content), 0o755); err != nil {
		t.Fatalf("write staging: %v", err)
	}
	manifest := fmt.Sprintf(`{"schema":1,"package_id":%q,"version":%q,"version_code":%d,`+
		`"min_nervus_api":1,"target_nervus_api":1,"supported_abis":[%q],`+
		`"digests":{"bin":%q},`+
		`"components":[{"id":"main","type":"app","entry":"bin","runtime":"native","launch_mode":"manual"}]}`,
		packageID, version, versionCode, testABI(), hashOf(content))
	return staging, []byte(manifest)
}

func installOnce(t *testing.T, mod *Module, manifestBytes, sig []byte, staging string) error {
	t.Helper()
	writeStagingMetadata(t, staging, manifestBytes, sig)
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	return err
}

func writeDevMode(t *testing.T, mod *Module, opts DevMode) {
	t.Helper()
	if err := os.MkdirAll(mod.stateDir, 0o700); err != nil {
		t.Fatalf("mkdir stateDir: %v", err)
	}
	f := devModeFile{Enabled: true, Options: opts}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal devmode: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mod.stateDir, devModeStateFile), data, 0o600); err != nil {
		t.Fatalf("write devmode: %v", err)
	}
}

func TestUpgrade_LineageRotationAccepted(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1)

	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m1, a.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v1 (root A): %v", err)
	}

	ab := a.extend(t)
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	if err := installOnce(t, mod, m2, ab.signWithLineage(t, m2), s2); err != nil {
		t.Fatalf("upgrade v2 (rotated A -> B) should be accepted: %v", err)
	}

	e, _ := mod.registry.Lookup("com.example.app")
	if e.VersionCode != 200 {
		t.Fatalf("active version_code = %d, want 200", e.VersionCode)
	}
}

func TestUpgrade_LineageForkRejected(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1)
	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m1, a.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v1: %v", err)
	}

	evil := newLineage(t, 1)
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	err := installOnce(t, mod, m2, evil.signWithLineage(t, m2), s2)
	if err == nil {
		t.Fatal("fork (different root) must be rejected as identity hijack")
	}
	e, _ := mod.registry.Lookup("com.example.app")
	if e.VersionCode != 100 {
		t.Fatalf("registry mutated by rejected fork: version_code=%d", e.VersionCode)
	}
}

func TestUpgrade_LineageShrinkRejected(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1)
	ab := a.extend(t)

	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m1, ab.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v1 (lineage len 2): %v", err)
	}

	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	err := installOnce(t, mod, m2, a.signWithLineage(t, m2), s2)
	if err == nil {
		t.Fatal("shrunk lineage (rollback to leaked key) must be rejected")
	}
}

func TestUpgrade_LineageOverlongRejected(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	long := newLineage(t, maxLineageNodes+1)
	s, m := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	err := installOnce(t, mod, m, long.signWithLineage(t, m), s)
	if err == nil {
		t.Fatalf("lineage with %d nodes must be rejected (cap %d)", maxLineageNodes+1, maxLineageNodes)
	}
}

func TestFreshInstall_AcceptsAnyVersionAndKey(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1)
	s1, m1 := stagingForVersion(t, t.TempDir(), "com.a", "9.9.9", 9999)
	if err := installOnce(t, mod, m1, a.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("fresh install high version: %v", err)
	}
	b := newLineage(t, 1)
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.b", "0.0.1", 1)
	if err := installOnce(t, mod, m2, b.signWithLineage(t, m2), s2); err != nil {
		t.Fatalf("fresh install unrelated key/low version: %v", err)
	}
}

func TestUpgrade_DevModeRelaxesDowngrade(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	key := newLineage(t, 1)

	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	if err := installOnce(t, mod, m1, key.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v200: %v", err)
	}

	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m2, key.signWithLineage(t, m2), s2); err == nil {
		t.Fatal("downgrade without devmode must be rejected")
	}

	writeDevMode(t, mod, DevMode{AllowDowngrade: true})
	s3, m3 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m3, key.signWithLineage(t, m3), s3); err != nil {
		t.Fatalf("downgrade with devmode allow_downgrade should be accepted: %v", err)
	}
}

func TestUpgrade_DevModeNeverRelaxesLineage(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1)
	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m1, a.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v1: %v", err)
	}

	writeDevMode(t, mod, DevMode{
		AllowUnverifiedSignature: true, AllowDowngrade: true, SkipOEMCountersign: true,
	})
	evil := newLineage(t, 1)
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	err := installOnce(t, mod, m2, evil.signWithLineage(t, m2), s2)
	if err == nil {
		t.Fatal("lineage discontinuity must be rejected EVEN with all devmode flags on")
	}
	e, _ := mod.registry.Lookup("com.example.app")
	if e.VersionCode != 100 || e.Trust != identity.TrustOrdinary {
		t.Fatalf("registry mutated by rejected hijack: %+v", e)
	}
}
