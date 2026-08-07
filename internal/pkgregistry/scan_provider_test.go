package pkgregistry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pkgmanagerv1 "github.com/nervus-os/nervus-ipc/protocol/interface/pkgmanagerv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

// writeSystemPackage 在 systemPackagesDir 下摆出一个【与 build-image-tree.sh 产物
// 同形】的系统包：二进制 + provider.binpb + schemas.binpb + manifest.json + manifest.sig。
//
// 这是本仓库唯一一处从磁盘走完整条装载路径的测试。它覆盖的是
// nervus-system-server 的 providergen/sysmanifest 与内核 scanSystemImage 之间的
// 那条缝——两边的字段名、文件名、digest 口径任何一处对不上都会在这里断。
func writeSystemPackage(t *testing.T, systemPackagesDir, packageID string, withProvider bool) {
	t.Helper()
	pkgDir := filepath.Join(systemPackagesDir, packageID)
	if err := os.MkdirAll(filepath.Join(pkgDir, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "bin", "svc"), []byte("ELF\n"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	m := Manifest{
		Schema:          1,
		PackageID:       packageID,
		Label:           "Scan Fixture",
		Version:         "0.1.0",
		VersionCode:     1,
		MinNervusAPI:    1,
		TargetNervusAPI: 1,
		SupportedABIs:   []string{ABILinuxX86_64, ABILinuxArm64},
		Permissions:     []string{"perm.service.register"},
		Components: []Component{{
			ID:         "main",
			Type:       ComponentService,
			Runtime:    RuntimeNative,
			Entry:      "bin/svc",
			LaunchMode: LaunchAlwaysOn,
			Exports: []Export{{
				Interface:  catalog.InterfacePackageManager,
				Visibility: VisibilityPublic,
			}},
		}},
	}

	if withProvider {
		descriptorWire, schemaWire := providergenBytes(t, packageID)
		if err := os.WriteFile(filepath.Join(pkgDir, "provider.binpb"), descriptorWire, 0o644); err != nil {
			t.Fatalf("write provider.binpb: %v", err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "schemas.binpb"), schemaWire, 0o644); err != nil {
			t.Fatalf("write schemas.binpb: %v", err)
		}
		m.Provider = &ProviderArtifactsRef{
			Descriptor: "provider.binpb",
			Schemas:    "schemas.binpb",
		}
	}

	m.Digests = fixtureDigests(t, pkgDir)

	manifestBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "manifest.json"), manifestBytes, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	writePlatformSignature(t, pkgDir, manifestBytes)
}

// fixtureDigests 复刻 sysmanifest computeDigests：遍历全部普通文件，
// 排除 manifest.json 与 manifest.sig（它们不能自散列）。
func fixtureDigests(t *testing.T, pkgDir string) map[string]string {
	t.Helper()
	digests := make(map[string]string)
	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !info.Mode().IsRegular() {
			return err
		}
		rel, rerr := filepath.Rel(pkgDir, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" || rel == SignatureFileName {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(data)
		digests[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("compute digests: %v", err)
	}
	return digests
}

// writePlatformSignature 用 platform-release 角色签名并内嵌公钥——与 sysmanifest
// 的 signManifest 同形，这样 LoadDevTrustStore 才锚得出这把钥匙。
func writePlatformSignature(t *testing.T, pkgDir string, manifestBytes []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msg := append(append([]byte{}, manifestSigDomain...), manifestBytes...)
	sig := ed25519.Sign(priv, msg)
	block := SignatureBlock{Format: 1, Signatures: []Signature{{
		Role:  RolePlatformRelease,
		Alg:   SigAlgEd25519,
		KeyID: keyIDOf(pub),
		Key:   base64.StdEncoding.EncodeToString(pub),
		Sig:   base64.StdEncoding.EncodeToString(sig),
	}}}
	data, err := json.Marshal(block)
	if err != nil {
		t.Fatalf("marshal sig: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, SignatureFileName), data, 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
}

// providergenBytes 复刻 nervus-system-server 的 pkgmanagerd/providergen 输出。
func providergenBytes(t *testing.T, packageID string) (descriptorWire, schemaWire []byte) {
	t.Helper()
	bundle, err := ipcregistry.BuildSchemaBundle(
		catalog.InterfacePackageManager, 1, pkgmanagerv1.PackageManagerMethod(0).Descriptor())
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptorWire, schemaWire, err = ipcregistry.MarshalProviderArtifacts(
		&ipcv1.ProviderDescriptor{
			PackageId: packageID,
			Interfaces: []*ipcv1.ProvidedInterface{{
				InterfaceId: catalog.InterfacePackageManager,
				InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
					Major: 1, SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
				}},
				RequiredPermission: "perm.pkg.query",
			}},
		},
		&ipcv1.InterfaceSchemaBundleSet{
			Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
		},
	)
	if err != nil {
		t.Fatalf("MarshalProviderArtifacts: %v", err)
	}
	return descriptorWire, schemaWire
}

// 带 Provider 契约的系统包必须完整装载：验签给到 Platform，provider 被解析，
// 并且能投影成一个可进 Catalog 的 Source。
func TestScanLoadsSystemPackageWithProviderArtifacts(t *testing.T) {
	stateDir := t.TempDir()
	systemPackagesDir := t.TempDir()
	writeSystemPackage(t, systemPackagesDir, "nervus.pkgmanagerd", true)

	trust, err := LoadDevTrustStore(systemPackagesDir, nil)
	if err != nil {
		t.Fatalf("LoadDevTrustStore: %v", err)
	}

	result := Scan(stateDir, systemPackagesDir, t.TempDir(), trust, nil)
	if len(result.Skipped) != 0 {
		t.Fatalf("包被跳过: %+v", result.Skipped)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("装载 %d 个包, want 1", len(result.Entries))
	}
	entry := result.Entries[0]
	if entry.Trust != identity.TrustPlatform {
		t.Errorf("trust = %v, want Platform", entry.Trust)
	}
	if entry.provider == nil || entry.provider.parsed == nil {
		t.Fatal("provider 契约未被解析")
	}
	if got := entry.provider.parsed.Descriptor.GetPackageId(); got != "nervus.pkgmanagerd" {
		t.Errorf("descriptor package_id = %q", got)
	}

	sources, err := projectCatalogSources(result.Entries)
	if err != nil {
		t.Fatalf("projectCatalogSources: %v", err)
	}
	if len(sources) != 1 || sources[0].Artifacts == nil {
		t.Fatalf("sources = %+v", sources)
	}
}

// 没有 Provider 契约的导出包必须被跳过——即便它就是 nervus.pkgmanagerd 本人，
// 即便签名与信任全部合格。这是兼容桥移除之后的硬约束。
func TestScanSkipsExportingPackageWithoutProviderArtifacts(t *testing.T) {
	stateDir := t.TempDir()
	systemPackagesDir := t.TempDir()
	writeSystemPackage(t, systemPackagesDir, "nervus.pkgmanagerd", false)

	trust, err := LoadDevTrustStore(systemPackagesDir, nil)
	if err != nil {
		t.Fatalf("LoadDevTrustStore: %v", err)
	}

	result := Scan(stateDir, systemPackagesDir, t.TempDir(), trust, nil)
	if len(result.Entries) != 0 {
		t.Fatalf("无 provider 契约的导出包被装载: %+v", result.Entries)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("跳过 %d 个, want 1", len(result.Skipped))
	}
}
