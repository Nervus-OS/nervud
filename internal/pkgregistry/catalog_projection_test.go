package pkgregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	dogv1 "github.com/nervus-os/nervus-ipc/protocol/oem/acme/dog/v1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

func TestPreparedProviderPublishesWithoutCapabilitySpecificKernelCode(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)
	entry := testOEMProviderEntry(t)

	prepared, err := mod.prepareEntries(context.Background(), []Entry{entry})
	if err != nil {
		t.Fatalf("prepareEntries: %v", err)
	}
	if _, ok := mod.definitions.Current().ProviderInterface(
		"com.acme.dog", "com.acme.dog.interface.raw_gait", 1,
	); ok {
		t.Fatal("Prepare made the provider routable")
	}
	if err := mod.publishCatalogLast(context.Background(), nil, prepared); err != nil {
		t.Fatalf("publishCatalogLast: %v", err)
	}
	method, ok := mod.definitions.Current().ProviderMethod(
		"com.acme.dog", "com.acme.dog.interface.raw_gait", 1, 2,
	)
	if !ok || method.Request == nil ||
		string(method.Request.FullName()) != "com.acme.dog.v1.SetRawGaitRequest" {
		t.Fatalf("provider method = %+v, %v", method, ok)
	}
}

func TestCatalogPublicationRevokesRemovedResourceAuthority(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)
	revoker := &fakeTransferRevoker{}
	mod.SetTransferRevoker(revoker)
	entry := testOEMProviderEntry(t)

	withProvider, err := mod.prepareEntries(context.Background(), []Entry{entry})
	if err != nil {
		t.Fatalf("prepare provider: %v", err)
	}
	if err := mod.publishCatalogLast(context.Background(), nil, withProvider); err != nil {
		t.Fatalf("publish provider: %v", err)
	}
	if len(revoker.resources) != 0 {
		t.Fatalf("new resource was treated as stale authority: %v", revoker.resources)
	}
	oldResource, ok := mod.definitions.Current().ResourceByHandle("gait.main")
	if !ok || oldResource.DefinitionGeneration == 0 {
		t.Fatalf("published resource = %+v, ok=%v", oldResource, ok)
	}

	withoutProvider, err := mod.prepareEntries(context.Background(), nil)
	if err != nil {
		t.Fatalf("prepare removal: %v", err)
	}
	if err := mod.publishCatalogLast(context.Background(), []Entry{entry}, withoutProvider); err != nil {
		t.Fatalf("publish removal: %v", err)
	}
	wantRevocation := catalog.RevokedResource{
		Handle: "gait.main", Generation: oldResource.DefinitionGeneration,
	}
	if len(revoker.resources) != 1 || revoker.resources[0] != wantRevocation {
		t.Fatalf("resource revocations = %v, want [%+v]", revoker.resources, wantRevocation)
	}
}

func TestConflictingProviderDefinitionsRejectWholeBatch(t *testing.T) {
	mod, _, _, _, _ := newTestInstallerWithPerm(t)
	before := mod.definitions.Current()
	left := testPermissionProviderEntry(
		t, "nervus.test.alpha", "perm.test.shared", "platform-key-alpha",
	)
	right := testPermissionProviderEntry(
		t, "nervus.test.beta", "perm.test.shared", "platform-key-beta",
	)

	if _, err := mod.prepareEntries(context.Background(), []Entry{left, right}); err == nil {
		t.Fatal("prepareEntries accepted conflicting permission definitions")
	}
	if mod.definitions.Current() != before {
		t.Fatal("rejected batch changed the current catalog")
	}
	if mod.registry.Len() != 0 {
		t.Fatal("rejected batch changed the package registry")
	}
}

// 曾经有一条只给 nervus.pkgmanagerd 的无契约兼容桥。它已随打包链
// （nervus-system-server 的 providergen）落地而整段移除。
//
// 本测试断言【那条桥真的没了】：即便把身份条件全部凑齐——正确的 package ID、
// 正确的组件与接口、系统镜像来源、Platform 信任、已验证的 platform-release
// 签名者——只要没有 Provider 契约，projectCatalogSources 就必须拒绝。
//
// 反过来说：内核不再存在任何一条「因为你是某个特定的包，所以可以少交东西」的路径。
func TestNoPackageIDGetsAnArtifactLessBridge(t *testing.T) {
	base := legacyPackageManagerEntry()

	if _, err := projectCatalogSources([]Entry{base}); !errors.Is(
		err, ErrProviderArtifactsRequired,
	) {
		t.Fatalf("身份条件齐备的 pkgmanagerd 仍被放行，兼容桥没有真正移除: err = %v", err)
	}

	// 换成任意别的 package ID 同样是拒绝——拒绝的理由与包名无关
	other := cloneEntry(base)
	other.Manifest.PackageID = "com.example.provider"
	if _, err := projectCatalogSources([]Entry{other}); !errors.Is(
		err, ErrProviderArtifactsRequired,
	) {
		t.Fatalf("projectCatalogSources error = %v, want artifacts required", err)
	}
}

func TestPrepareEntriesRecomputesEveryGrantFromCandidate(t *testing.T) {
	mod, _, _, _, perm := newTestInstallerWithPerm(t)
	var calls int
	perm.intersectAt = func(
		snapshot *catalog.Snapshot,
		requested []string,
		source catalog.SourceKind,
		_ identity.TrustProfile,
		_ catalog.SignerEvidence,
	) ([]string, []string) {
		calls++
		if snapshot == nil || snapshot.Revision() == 0 {
			t.Fatal("IntersectAt received no candidate snapshot")
		}
		if source != catalog.SourceKindDynamicInstall {
			t.Fatalf("source = %v, want dynamic install", source)
		}
		return append([]string{"fresh"}, requested...), nil
	}
	entries := []Entry{
		{
			Manifest: Manifest{
				PackageID:   "com.example.one",
				Permissions: []string{"one"},
			},
			Source:             SourceDynamicInstall,
			Trust:              identity.TrustOrdinary,
			GrantedPermissions: []string{"stale-ledger-grant"},
		},
		{
			Manifest: Manifest{
				PackageID:   "com.example.two",
				Permissions: []string{"two"},
			},
			Source:             SourceDynamicInstall,
			Trust:              identity.TrustOrdinary,
			GrantedPermissions: []string{"another-stale-grant"},
		},
	}
	prepared, err := mod.prepareEntries(context.Background(), entries)
	if err != nil {
		t.Fatalf("prepareEntries: %v", err)
	}
	if calls != 2 {
		t.Fatalf("IntersectAt calls = %d, want 2", calls)
	}
	for i, want := range []string{"one", "two"} {
		got := prepared.entries[i].GrantedPermissions
		if len(got) != 2 || got[0] != "fresh" || got[1] != want {
			t.Fatalf("entry %d grants = %v", i, got)
		}
	}
}

func TestCatalogCASFailureRollsBackProjectionAndClearsGrants(t *testing.T) {
	mod, _, _, _, perm := newTestInstallerWithPerm(t)
	entry := Entry{
		Manifest: Manifest{
			PackageID:   "com.example.stale",
			Permissions: []string{"example.permission"},
		},
		ActiveVersion: "1.0.0",
		VersionCode:   1,
		UID:           20000,
		Trust:         identity.TrustOrdinary,
		Source:        SourceDynamicInstall,
	}
	prepared, err := mod.prepareEntries(context.Background(), []Entry{entry})
	if err != nil {
		t.Fatalf("prepareEntries: %v", err)
	}
	competing, err := mod.definitions.Prepare(nil)
	if err != nil || !mod.definitions.Publish(competing) {
		t.Fatalf("publish competing candidate: %v", err)
	}

	err = mod.publishCatalogLast(context.Background(), nil, prepared)
	if !errors.Is(err, ErrCatalogPublishConflict) {
		t.Fatalf("publishCatalogLast error = %v", err)
	}
	if mod.registry.Len() != 0 {
		t.Fatal("stale candidate left its package projection visible")
	}
	if len(perm.replaced) == 0 || perm.replaced[len(perm.replaced)-1] != nil {
		t.Fatalf("last permission projection = %#v, want fail-closed nil", perm.replaced)
	}
}

func TestInstallRejectsBadCatalogBeforeDiskOrLedger(t *testing.T) {
	mod, auth, _, _, _ := newTestInstallerWithPerm(t)
	staging, manifestBytes, sig := newIllegalProviderStaging(t, t.TempDir())

	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes,
		SigBlock:      sig,
		StagingDir:    staging,
		Source:        SourceDynamicInstall,
	})
	if err == nil {
		t.Fatal("Install accepted a dynamic provider defining a platform permission")
	}
	if len(auth.installed) != 0 || len(auth.dataDirs) != 0 || len(auth.appUsers) != 0 {
		t.Fatalf("authority was called before catalog rejection: %+v", auth)
	}
	statePath, pathErr := stateFilePath(mod.stateDir, "com.example.badprovider")
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	if _, statErr := os.Stat(statePath); !os.IsNotExist(statErr) {
		t.Fatalf("ledger exists after preflight rejection: %v", statErr)
	}
}

func TestDynamicScanReverifiesSignatureAndDropsPersistedGrant(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "registry")
	packageRoot := filepath.Join(root, "packages")
	finalDir := filepath.Join(packageRoot, "com.example.scanned", "1.0.0")
	staging, manifestBytes, sig := newValidStagingWithKey(
		t, t.TempDir(), "com.example.scanned", "1.0.0", 100, newDevKey(t),
	)
	if err := os.MkdirAll(finalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bin", ManifestFileName, SignatureFileName} {
		data, err := os.ReadFile(filepath.Join(staging, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(finalDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	signers, err := (TrustStore{}).VerifySignature(manifestBytes, sig)
	if err != nil || signers.Dev == nil {
		t.Fatalf("verify fixture: %v", err)
	}
	if err := saveRegistryState(stateDir, registryState{
		PackageID:          "com.example.scanned",
		ActiveVersion:      "1.0.0",
		VersionCode:        100,
		UID:                20000,
		Trust:              identity.TrustOrdinary.String(),
		Source:             SourceDynamicInstall.String(),
		GrantedPermissions: []string{"stale.persisted.grant"},
		LineageRootKeyID:   signers.Dev.RootKeyID,
		LineageKeyIDs:      signers.Dev.KeyIDs,
	}); err != nil {
		t.Fatal(err)
	}

	entries, skipped := scanDynamicInstalls(stateDir, packageRoot, TrustStore{}, nil)
	if len(skipped) != 0 || len(entries) != 1 {
		t.Fatalf("entries=%d skipped=%+v", len(entries), skipped)
	}
	if len(entries[0].GrantedPermissions) != 0 {
		t.Fatalf("persisted grant was trusted: %v", entries[0].GrantedPermissions)
	}
	if len(entries[0].VerifiedSigners) == 0 ||
		entries[0].DeveloperRootID != signers.Dev.RootKeyID {
		t.Fatalf("verified evidence missing: %+v", entries[0])
	}

	if err := os.WriteFile(
		filepath.Join(finalDir, SignatureFileName), []byte("tampered"), 0o644,
	); err != nil {
		t.Fatal(err)
	}
	entries, skipped = scanDynamicInstalls(stateDir, packageRoot, TrustStore{}, nil)
	if len(entries) != 0 || len(skipped) != 1 {
		t.Fatalf("tampered signature entries=%d skipped=%+v", len(entries), skipped)
	}
}

func testOEMProviderEntry(t *testing.T) Entry {
	t.Helper()
	const (
		packageID   = "com.acme.dog"
		interfaceID = "com.acme.dog.interface.raw_gait"
		permission  = "com.acme.dog.permission.raw_gait"
		resource    = "com.acme.dog.resource.gait_engine"
	)
	bundle, err := ipcregistry.BuildSchemaBundle(
		interfaceID, 1, dogv1.RawGaitMethod(0).Descriptor(),
	)
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: packageID,
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: interfaceID,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
			}},
			RequiredPermission:      permission,
			ResourceRiskFloor:       ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			CompatibleResourceTypes: []string{resource},
			DefaultResourceType:     resource,
			DefaultResourceRole:     "gait.main",
		}},
		Resources: []*ipcv1.ManagedResource{{
			StableRole:   "gait.main",
			ResourceType: resource,
			AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
		}},
		Permissions: []*ipcv1.DefinedPermission{testPermissionWire(
			permission,
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_OEM,
			string(RoleOEMService),
		)},
	}
	parsed := parseTestArtifacts(t, descriptor, &ipcv1.InterfaceSchemaBundleSet{
		Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
	})
	return Entry{
		Manifest: Manifest{
			PackageID: packageID,
			Components: []Component{{
				ID:      "main",
				Exports: []Export{{Interface: interfaceID}},
			}},
			Provider: &ProviderArtifactsRef{
				Descriptor: "provider.pb",
				Schemas:    "schemas.pb",
			},
		},
		ActiveVersion: "1.0.0",
		VersionCode:   1,
		UID:           20000,
		Trust:         identity.TrustOEM,
		Source:        SourceSystemImage,
		SignerRoles:   []string{string(RoleOEMService)},
		VerifiedSigners: []VerifiedSigner{{
			Role: RoleOEMService, KeyID: "verified-oem-service-key",
		}},
		provider: &loadedProviderArtifacts{parsed: parsed},
	}
}

func testPermissionProviderEntry(
	t *testing.T,
	packageID string,
	permissionID string,
	keyID string,
) Entry {
	t.Helper()
	parsed := parseTestArtifacts(t, &ipcv1.ProviderDescriptor{
		PackageId: packageID,
		Permissions: []*ipcv1.DefinedPermission{testPermissionWire(
			permissionID,
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
		)},
	}, &ipcv1.InterfaceSchemaBundleSet{})
	return Entry{
		Manifest: Manifest{
			PackageID: packageID,
			Provider: &ProviderArtifactsRef{
				Descriptor: "provider.pb",
				Schemas:    "schemas.pb",
			},
		},
		ActiveVersion: "1.0.0",
		VersionCode:   1,
		UID:           20000,
		Trust:         identity.TrustPlatform,
		Source:        SourceSystemImage,
		SignerRoles:   []string{string(RolePlatformRelease)},
		VerifiedSigners: []VerifiedSigner{{
			Role: RolePlatformRelease, KeyID: keyID,
		}},
		provider: &loadedProviderArtifacts{parsed: parsed},
	}
}

// legacyPackageManagerEntry 造一个「身份条件全部齐备、只差 Provider 契约」的
// pkgmanagerd Entry。兼容桥还在时它能被放行；现在它只用来证明放行路径已消失。
func legacyPackageManagerEntry() Entry {
	return Entry{
		Manifest: Manifest{
			PackageID: "nervus.pkgmanagerd",
			Components: []Component{{
				ID: "main",
				Exports: []Export{{
					Interface: catalog.InterfacePackageManager,
				}},
			}},
		},
		ActiveVersion: "1.0.0",
		VersionCode:   1,
		UID:           20000,
		Trust:         identity.TrustPlatform,
		Source:        SourceSystemImage,
		SignerRoles:   []string{string(RolePlatformRelease)},
		VerifiedSigners: []VerifiedSigner{{
			Role: RolePlatformRelease, KeyID: "verified-platform-release-key",
		}},
	}
}

func parseTestArtifacts(
	t *testing.T,
	descriptor *ipcv1.ProviderDescriptor,
	schemas *ipcv1.InterfaceSchemaBundleSet,
) *ipcregistry.ProviderArtifacts {
	t.Helper()
	marshal := proto.MarshalOptions{Deterministic: true}
	descriptorWire, err := marshal.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	schemaWire, err := marshal.Marshal(schemas)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}
	return parsed
}

func testPermissionWire(
	id string,
	mode ipcv1.GrantMode,
	risk ipcv1.RiskClass,
	minimum ipcv1.PermissionTrustFloor,
	role string,
) *ipcv1.DefinedPermission {
	return &ipcv1.DefinedPermission{
		Id:                 id,
		GrantMode:          mode,
		RiskClass:          risk,
		MinimumTrust:       minimum,
		RequiredSignerRole: role,
		DisplayName:        &ipcv1.LocalizedText{ZhCn: "测试", En: "Test"},
		Description:        &ipcv1.LocalizedText{ZhCn: "测试说明", En: "Test description"},
	}
}

func newIllegalProviderStaging(t *testing.T, root string) (string, []byte, []byte) {
	t.Helper()
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := []byte("#!/bin/true")
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: "com.example.badprovider",
		Permissions: []*ipcv1.DefinedPermission{testPermissionWire(
			"perm.microphone.capture",
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
		)},
	}
	marshal := proto.MarshalOptions{Deterministic: true}
	descriptorWire, err := marshal.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	schemaWire, err := marshal.Marshal(&ipcv1.InterfaceSchemaBundleSet{})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"bin":         bin,
		"provider.pb": descriptorWire,
		"schemas.pb":  schemaWire,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(staging, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	digests := make(map[string]string, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		digests[name] = hex.EncodeToString(sum[:])
	}
	manifest := map[string]any{
		"schema":            1,
		"package_id":        "com.example.badprovider",
		"version":           "1.0.0",
		"version_code":      1,
		"min_nervus_api":    1,
		"target_nervus_api": 1,
		"supported_abis":    []string{testABI()},
		"digests":           digests,
		"provider": map[string]string{
			"descriptor": "provider.pb",
			"schemas":    "schemas.pb",
		},
		"components": []map[string]any{{
			"id":          "main",
			"type":        "app",
			"entry":       "bin",
			"runtime":     "native",
			"launch_mode": "manual",
		}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig := signManifest(t, newDevKey(t), manifestBytes)
	writeStagingMetadata(t, staging, manifestBytes, sig)
	return staging, manifestBytes, sig
}
