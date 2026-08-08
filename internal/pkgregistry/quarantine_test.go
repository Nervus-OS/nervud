package pkgregistry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

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

func TestDropEntry(t *testing.T) {
	entries := []Entry{
		{Manifest: Manifest{PackageID: "a"}},
		{Manifest: Manifest{PackageID: "b"}},
		{Manifest: Manifest{PackageID: "c"}},
	}
	next, victim, ok := dropEntry(entries, "b")
	if !ok {
		t.Fatal("unexpected package registry result; dropEntry b")
	}
	if victim.Manifest.PackageID != "b" {
		t.Errorf("victim = %q, want b", victim.Manifest.PackageID)
	}
	if len(next) != 2 || next[0].Manifest.PackageID != "a" || next[1].Manifest.PackageID != "c" {
		t.Errorf("next = %+v", next)
	}
	if len(entries) != 3 || entries[1].Manifest.PackageID != "b" {
		t.Error("unexpected package registry result; dropEntry")
	}

	if _, _, ok := dropEntry(entries, "zzz"); ok {
		t.Error("unexpected package registry result; dropEntry")
	}
}

//

func TestQuarantine_BadPackageDoesNotBlockBoot(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)

	good := testOEMProviderEntry(t)
	bad := entryMissingProviderArtifacts("com.bad.provider", 20099)

	prepared, quarantined, err := mod.prepareEntriesQuarantining(
		context.Background(), []Entry{good, bad})
	if err != nil {
		t.Fatalf("unexpected package registry result; value = %v", err)
	}
	if len(quarantined) != 1 || quarantined[0].Manifest.PackageID != "com.bad.provider" {
		t.Fatalf("quarantined = %+v, want [com.bad.provider]", quarantined)
	}
	if prepared.candidate == nil {
		t.Fatal("unexpected package registry result; candidate")
	}

	if _, ok := prepared.candidate.Snapshot().ProviderInterface(
		"com.acme.dog", "com.acme.dog.interface.raw_gait", 1); !ok {
		t.Error("unexpected package registry result")
	}
}

func TestQuarantine_MultipleBadPackages(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)

	entries := []Entry{
		entryMissingProviderArtifacts("com.bad.one", 20001),
		testOEMProviderEntry(t),
		entryMissingProviderArtifacts("com.bad.two", 20002),
	}

	prepared, quarantined, err := mod.prepareEntriesQuarantining(context.Background(), entries)
	if err != nil {
		t.Fatalf("unexpected package registry result; value = %v", err)
	}
	if len(quarantined) != 2 {
		t.Fatalf("unexpected package registry result; value = %d, want 2", len(quarantined))
	}
	got := map[string]bool{}
	for _, e := range quarantined {
		got[e.Manifest.PackageID] = true
	}
	if !got["com.bad.one"] || !got["com.bad.two"] {
		t.Errorf("unexpected package registry result; value = %v", got)
	}
	if prepared.candidate == nil {
		t.Fatal("unexpected package registry result; candidate")
	}
}

func TestQuarantine_AllPackagesBadStillBoots(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)

	entries := []Entry{
		entryMissingProviderArtifacts("com.bad.one", 20001),
		entryMissingProviderArtifacts("com.bad.two", 20002),
	}
	prepared, quarantined, err := mod.prepareEntriesQuarantining(context.Background(), entries)
	if err != nil {
		t.Fatalf("unexpected package registry result; value = %v", err)
	}
	if len(quarantined) != 2 {
		t.Fatalf("unexpected package registry result; value = %d, want 2", len(quarantined))
	}
	if prepared.candidate == nil {
		t.Fatal("unexpected package registry result; candidate bootstrap")
	}
}

func TestQuarantine_NonSourceFailureIsReturned(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)
	mod.definitions = nil

	if _, _, err := mod.prepareEntriesQuarantining(context.Background(), nil); !errors.Is(
		err, ErrCatalogUnavailable,
	) {
		t.Fatalf("err = %v, want ErrCatalogUnavailable", err)
	}
}

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

func TestSourceErrorUnwrapsToSentinel(t *testing.T) {
	err := error(&catalog.SourceError{
		PackageID: "com.example.app",
		Err:       ErrProviderArtifactsRequired,
	})
	if !errors.Is(err, ErrProviderArtifactsRequired) {
		t.Fatal("unexpected package registry result; errors.Is SourceError")
	}
	var srcErr *catalog.SourceError
	if !errors.As(err, &srcErr) || srcErr.PackageID != "com.example.app" {
		t.Fatalf("unexpected package registry result; errors.As PackageID: %+v", srcErr)
	}
	if !strings.Contains(err.Error(), "com.example.app") {
		t.Errorf("unexpected package registry result; value = %s", err.Error())
	}
}
