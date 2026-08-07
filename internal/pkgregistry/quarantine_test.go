package pkgregistry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

// entryMissingProviderArtifacts 造一个「有 exports 却没有 Provider 契约」的包。
// 这是升级内核后最常见的一种坏包：服务侧还没重新打包就装上去了。
func entryMissingProviderArtifacts(pkgID string, uid uint32) Entry {
	return Entry{
		Manifest: Manifest{
			PackageID: pkgID,
			Components: []Component{{
				ID:      "main",
				Exports: []Export{{Interface: pkgID + ".interface.thing"}},
			}},
		},
		ActiveVersion:   "1.0.0",
		VersionCode:     1,
		UID:             uid,
		Trust:           identity.TrustOEM,
		Source:          SourceSystemImage,
		SignerRoles:     []string{string(RoleOEMService)},
		VerifiedSigners: []VerifiedSigner{{Role: RoleOEMService, KeyID: pkgID + "-key"}},
	}
}

// dropEntry 是隔离循环的基石：必须真的剔除，且【不能】改动入参切片——
// 调用方仍持有原集合用于审计。
func TestDropEntry(t *testing.T) {
	entries := []Entry{
		{Manifest: Manifest{PackageID: "a"}},
		{Manifest: Manifest{PackageID: "b"}},
		{Manifest: Manifest{PackageID: "c"}},
	}
	next, victim, ok := dropEntry(entries, "b")
	if !ok {
		t.Fatal("dropEntry 没找到 b")
	}
	if victim.Manifest.PackageID != "b" {
		t.Errorf("victim = %q, want b", victim.Manifest.PackageID)
	}
	if len(next) != 2 || next[0].Manifest.PackageID != "a" || next[1].Manifest.PackageID != "c" {
		t.Errorf("next = %+v", next)
	}
	if len(entries) != 3 || entries[1].Manifest.PackageID != "b" {
		t.Error("dropEntry 改动了入参切片")
	}

	if _, _, ok := dropEntry(entries, "zzz"); ok {
		t.Error("dropEntry 报告找到了不存在的包")
	}
}

// 一个坏包必须被隔离，好包必须活下来。
//
// 这条锁住 Module.Start 注释里那句承诺——在此之前它对 Catalog 层的失败并不成立：
// 一个缺契约的包会让 prepareEntries 整体失败，进而让整台机器起不来。
func TestQuarantine_BadPackageDoesNotBlockBoot(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)

	good := testOEMProviderEntry(t)
	bad := entryMissingProviderArtifacts("com.bad.provider", 20099)

	prepared, quarantined, err := mod.prepareEntriesQuarantining(
		context.Background(), []Entry{good, bad})
	if err != nil {
		t.Fatalf("启动被一个坏包拖垮了: %v", err)
	}
	if len(quarantined) != 1 || quarantined[0].Manifest.PackageID != "com.bad.provider" {
		t.Fatalf("quarantined = %+v, want [com.bad.provider]", quarantined)
	}
	if prepared.candidate == nil {
		t.Fatal("没有产出 candidate")
	}
	// 好包必须仍在 Catalog 里
	if _, ok := prepared.candidate.Snapshot().ProviderInterface(
		"com.acme.dog", "com.acme.dog.interface.raw_gait", 1); !ok {
		t.Error("好包被坏包连累了")
	}
}

// 多个坏包要逐个隔离，一轮一个，直到剩下的能构建出来。
func TestQuarantine_MultipleBadPackages(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)

	entries := []Entry{
		entryMissingProviderArtifacts("com.bad.one", 20001),
		testOEMProviderEntry(t),
		entryMissingProviderArtifacts("com.bad.two", 20002),
	}

	prepared, quarantined, err := mod.prepareEntriesQuarantining(context.Background(), entries)
	if err != nil {
		t.Fatalf("两个坏包让启动失败了: %v", err)
	}
	if len(quarantined) != 2 {
		t.Fatalf("隔离了 %d 个, want 2", len(quarantined))
	}
	got := map[string]bool{}
	for _, e := range quarantined {
		got[e.Manifest.PackageID] = true
	}
	if !got["com.bad.one"] || !got["com.bad.two"] {
		t.Errorf("隔离的包不对: %v", got)
	}
	if prepared.candidate == nil {
		t.Fatal("没有产出 candidate")
	}
}

// 全都是坏包时仍要能起来——只是 Catalog 里除了内核 bootstrap 什么都没有。
func TestQuarantine_AllPackagesBadStillBoots(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)

	entries := []Entry{
		entryMissingProviderArtifacts("com.bad.one", 20001),
		entryMissingProviderArtifacts("com.bad.two", 20002),
	}
	prepared, quarantined, err := mod.prepareEntriesQuarantining(context.Background(), entries)
	if err != nil {
		t.Fatalf("全坏包让启动失败了: %v", err)
	}
	if len(quarantined) != 2 {
		t.Fatalf("隔离了 %d 个, want 2", len(quarantined))
	}
	if prepared.candidate == nil {
		t.Fatal("没有产出 candidate（内核 bootstrap 本身应当仍然成立）")
	}
}

// 没有包可隔离的失败（Catalog 不可用）必须原样上报：隔离任何包都无济于事，
// 假装成功会让内核带着一份空 Catalog 继续跑。
func TestQuarantine_NonSourceFailureIsReturned(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)
	mod.definitions = nil

	if _, _, err := mod.prepareEntriesQuarantining(context.Background(), nil); !errors.Is(
		err, ErrCatalogUnavailable,
	) {
		t.Fatalf("err = %v, want ErrCatalogUnavailable", err)
	}
}

// 安装路径【不走】隔离：新包有问题就该拒绝新包，不能悄悄把它丢掉再宣告成功。
func TestInstallPathKeepsAllOrNothing(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)

	entries := []Entry{
		testOEMProviderEntry(t),
		entryMissingProviderArtifacts("com.bad.provider", 20099),
	}
	if _, err := mod.prepareEntries(context.Background(), entries); !errors.Is(
		err, ErrProviderArtifactsRequired,
	) {
		t.Fatalf("prepareEntries err = %v, want ErrProviderArtifactsRequired", err)
	}
}

// SourceError 必须保留内层 sentinel，否则调用方的 errors.Is 判定会静默失效，
// 而隔离循环正是靠 errors.As 取 PackageID 的。
func TestSourceErrorUnwrapsToSentinel(t *testing.T) {
	err := error(&catalog.SourceError{
		PackageID: "com.example.app",
		Err:       ErrProviderArtifactsRequired,
	})
	if !errors.Is(err, ErrProviderArtifactsRequired) {
		t.Fatal("errors.Is 穿不过 SourceError")
	}
	var srcErr *catalog.SourceError
	if !errors.As(err, &srcErr) || srcErr.PackageID != "com.example.app" {
		t.Fatalf("errors.As 取不出 PackageID: %+v", srcErr)
	}
	if !strings.Contains(err.Error(), "com.example.app") {
		t.Errorf("错误文案里没有包名: %s", err.Error())
	}
}
