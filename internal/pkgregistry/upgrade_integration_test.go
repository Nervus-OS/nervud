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

// Step 5：升级裁决集成测试（应用层架构决策 §2.4/§2.6/§4.1）。
//
// 覆盖：lineage 正常轮转 A→B 被接受、分叉被拒、变短被拒、超长链被拒、全新安装
// 接受任意版本/密钥、devmode 放宽 version_code 但【绝不】放宽 lineage 连续性。
//
// 与 install_test.go 的 signManifest（单签名、无 lineage）不同，本文件的
// signWithLineage 产出【带 lineage 链】的 manifest.sig，并把 developer 签名绑定
// 到整条血统（developerSignMessage），走的是真实升级路径。

// lineageChain 是一条测试用血统：私钥序列，nodes[0]=root，last=当前有效密钥
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

// extend 追加一把新密钥，返回更长的血统（原血统不变）——模拟密钥轮转
func (lc lineageChain) extend(t *testing.T) lineageChain {
	t.Helper()
	next := make([]ed25519.PrivateKey, len(lc.keys)+1)
	copy(next, lc.keys)
	next[len(lc.keys)] = newDevKey(t)
	return lineageChain{keys: next}
}

// buildLineage 把私钥序列构造成已逐跳签名的 *Lineage wire 结构
func (lc lineageChain) buildLineage(t *testing.T) *Lineage {
	t.Helper()
	if len(lc.keys) <= 1 {
		return nil // 单节点 = 无 lineage（TOFU），signWithLineage 会退回裸签名
	}
	nodes := make([]LineageNode, len(lc.keys))
	for i, k := range lc.keys {
		pub := k.Public().(ed25519.PublicKey)
		nodes[i] = LineageNode{KeyID: keyIDOf(pub), Key: base64.StdEncoding.EncodeToString(pub)}
		if i > 0 {
			// signed_by_prev = 用 nodes[i-1] 签 (lineageSigDomain || key_id || key)
			prev := lc.keys[i-1]
			msg := append(append(append([]byte{}, lineageSigDomain...), []byte(nodes[i].KeyID)...), pub...)
			nodes[i].SignedByPrev = base64.StdEncoding.EncodeToString(ed25519.Sign(prev, msg))
		}
	}
	return &Lineage{Format: lineageFormatV1, Nodes: nodes}
}

// signWithLineage 用当前有效密钥（最后一个节点）对 manifest 产出带 lineage 的 sig
func (lc lineageChain) signWithLineage(t *testing.T, manifestBytes []byte) []byte {
	t.Helper()
	lin := lc.buildLineage(t)
	cur := lc.keys[len(lc.keys)-1]
	pub := cur.Public().(ed25519.PublicKey)

	// developer 签名覆盖「manifest + 整条血统绑定」（P1-5：防中间人换血统毒化 root）
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

// stagingForVersion 造一份 version_code 可控的 staging（内容固定，只变版本），
// 返回 (staging, manifestBytes)。签名由调用方用 lineageChain 决定
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

// installOnce 是测试的便捷封装：装一次包，返回 Install 的 error。写入 staging 元数据
// 以满足 verifyStagingMetadata（落盘树的 manifest/sig 必须与验签字节一致）
func installOnce(t *testing.T, mod *Module, manifestBytes, sig []byte, staging string) error {
	t.Helper()
	writeStagingMetadata(t, staging, manifestBytes, sig)
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	return err
}

// writeDevMode 在 stateDir 写一个 devmode 记账文件
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

// ---- 1. 正常轮转 A→B 被接受 ----------------------------------------------

func TestUpgrade_LineageRotationAccepted(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1) // 单节点 root=A

	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m1, a.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v1 (root A): %v", err)
	}

	// 轮转：A 授权 B 接替，用 B 签 v2
	ab := a.extend(t)
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	if err := installOnce(t, mod, m2, ab.signWithLineage(t, m2), s2); err != nil {
		t.Fatalf("upgrade v2 (rotated A→B) should be accepted: %v", err)
	}

	e, _ := mod.registry.Lookup("com.example.app")
	if e.VersionCode != 200 {
		t.Fatalf("active version_code = %d, want 200", e.VersionCode)
	}
}

// ---- 2. 分叉被拒（另起炉灶的新 root） -------------------------------------

func TestUpgrade_LineageForkRejected(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1)
	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m1, a.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v1: %v", err)
	}

	// 完全不同的另一条血统（不同 root），冒充升级
	evil := newLineage(t, 1)
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	err := installOnce(t, mod, m2, evil.signWithLineage(t, m2), s2)
	if err == nil {
		t.Fatal("fork (different root) must be rejected as identity hijack")
	}
	// 升级失败后 Registry 必须仍是 v1，未被劫持
	e, _ := mod.registry.Lookup("com.example.app")
	if e.VersionCode != 100 {
		t.Fatalf("registry mutated by rejected fork: version_code=%d", e.VersionCode)
	}
}

// ---- 3. 变短被拒（回退到已泄漏的旧密钥） ----------------------------------

func TestUpgrade_LineageShrinkRejected(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1)
	ab := a.extend(t) // 长度 2：A→B

	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m1, ab.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v1 (lineage len 2): %v", err)
	}

	// 攻击者只握有已泄漏的旧密钥 A，试图用更短的血统（仅 A）顶替
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	err := installOnce(t, mod, m2, a.signWithLineage(t, m2), s2)
	if err == nil {
		t.Fatal("shrunk lineage (rollback to leaked key) must be rejected")
	}
}

// ---- 4. 超长链被拒（节点数 > 16） ----------------------------------------

func TestUpgrade_LineageOverlongRejected(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	// 17 个节点，超过 maxLineageNodes=16
	long := newLineage(t, maxLineageNodes+1)
	s, m := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	err := installOnce(t, mod, m, long.signWithLineage(t, m), s)
	if err == nil {
		t.Fatalf("lineage with %d nodes must be rejected (cap %d)", maxLineageNodes+1, maxLineageNodes)
	}
}

// ---- 5. 全新安装接受任意版本 / 任意密钥 -----------------------------------

func TestFreshInstall_AcceptsAnyVersionAndKey(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	// 全新安装一个高 version_code
	a := newLineage(t, 1)
	s1, m1 := stagingForVersion(t, t.TempDir(), "com.a", "9.9.9", 9999)
	if err := installOnce(t, mod, m1, a.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("fresh install high version: %v", err)
	}
	// 另一个全新包用完全无关的密钥、低 version_code——全新安装无可继承，都应接受
	b := newLineage(t, 1)
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.b", "0.0.1", 1)
	if err := installOnce(t, mod, m2, b.signWithLineage(t, m2), s2); err != nil {
		t.Fatalf("fresh install unrelated key/low version: %v", err)
	}
}

// ---- 6a. devmode 放宽 version_code 防降级 ---------------------------------

func TestUpgrade_DevModeRelaxesDowngrade(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	key := newLineage(t, 1)

	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "2.0.0", 200)
	if err := installOnce(t, mod, m1, key.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v200: %v", err)
	}

	// 无 devmode：降级到 100 必须被拒
	s2, m2 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m2, key.signWithLineage(t, m2), s2); err == nil {
		t.Fatal("downgrade without devmode must be rejected")
	}

	// 开 devmode allow_downgrade：同一把密钥（lineage 仍连续）降级应被放行
	writeDevMode(t, mod, DevMode{AllowDowngrade: true})
	s3, m3 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m3, key.signWithLineage(t, m3), s3); err != nil {
		t.Fatalf("downgrade with devmode allow_downgrade should be accepted: %v", err)
	}
}

// ---- 6b. devmode 【绝不】放宽 lineage 连续性 ------------------------------

func TestUpgrade_DevModeNeverRelaxesLineage(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	a := newLineage(t, 1)
	s1, m1 := stagingForVersion(t, t.TempDir(), "com.example.app", "1.0.0", 100)
	if err := installOnce(t, mod, m1, a.signWithLineage(t, m1), s1); err != nil {
		t.Fatalf("install v1: %v", err)
	}

	// 即便打开【全部】devmode 放宽开关，用不同 root 的血统升级仍必须被拒——
	// 签名连续性是防身份劫持的底线，devmode 也不放宽（§2.6）
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
