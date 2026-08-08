package catalog

import (
	"testing"

	pkgmanagerv1 "github.com/nervus-os/nervus-ipc/protocol/interface/pkgmanagerv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"

	"github.com/nervus-os/nervud/internal/identity"
)

//

func providergenStyleArtifacts(t *testing.T) *ipcregistry.ProviderArtifacts {
	t.Helper()
	bundle, err := ipcregistry.BuildSchemaBundle(
		InterfacePackageManager, 1, pkgmanagerv1.PackageManagerMethod(0).Descriptor())
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: "nervus.pkgmanagerd",
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: InterfacePackageManager,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
			}},
			RequiredPermission: "perm.pkg.query",
		}},
	}
	set := &ipcv1.InterfaceSchemaBundleSet{
		Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
	}
	descriptorWire, schemaWire, err := ipcregistry.MarshalProviderArtifacts(descriptor, set)
	if err != nil {
		t.Fatalf("MarshalProviderArtifacts: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}
	return artifacts
}

//

func TestProvidergenArtifactsMatchBootstrapContract(t *testing.T) {
	registry := mustDefaultRegistry(t)
	candidate, err := registry.Prepare([]Source{{
		PackageID: "nervus.pkgmanagerd",
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustPlatform,
		Signers: SignerEvidence{
			Roles: []string{rolePlatformRelease},
			VerifiedSigners: []VerifiedSigner{{
				Role: rolePlatformRelease, KeyID: "platform-release-key",
			}},
		},
		Exports: []ExportBinding{{
			ComponentID: "main",
			InterfaceID: InterfacePackageManager,
		}},
		Artifacts: providergenStyleArtifacts(t),
	}})
	if err != nil {
		t.Fatalf("Prepare with providergen-style artifacts: %v", err)
	}

	method, ok := candidate.Snapshot().ProviderMethod(
		"nervus.pkgmanagerd", InterfacePackageManager, 1, 1)
	if !ok || method.Request == nil ||
		string(method.Request.FullName()) != "nervus.interface.pkgmanager.v1.InstallRequest" {
		t.Fatalf("package-manager method = %+v, %v", method, ok)
	}
	iface, ok := candidate.Snapshot().Interface(InterfacePackageManager, 1)
	if !ok || iface.RequiredPermission != "perm.pkg.query" {
		t.Fatalf("interface permission = %q, %v; want perm.pkg.query", iface.RequiredPermission, ok)
	}

	query, ok := candidate.Snapshot().Permission("perm.pkg.query")
	if !ok || query.GrantMode != ipcv1.GrantMode_GRANT_MODE_NORMAL {
		t.Fatalf("package query permission = %+v, %v", query, ok)
	}
	install, ok := candidate.Snapshot().Permission("perm.pkg.install")
	if !ok || install.GrantMode != ipcv1.GrantMode_GRANT_MODE_USER_CONSENT {
		t.Fatalf("package install permission = %+v, %v", install, ok)
	}
}

func TestProvidergenArtifactsWithWrongPermissionConflict(t *testing.T) {
	bundle, err := ipcregistry.BuildSchemaBundle(
		InterfacePackageManager, 1, pkgmanagerv1.PackageManagerMethod(0).Descriptor())
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: "nervus.pkgmanagerd",
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: InterfacePackageManager,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
			}},

			RequiredPermission: "perm.pkg.install",
		}},
	}
	descriptorWire, schemaWire, err := ipcregistry.MarshalProviderArtifacts(
		descriptor, &ipcv1.InterfaceSchemaBundleSet{
			Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
		})
	if err != nil {
		t.Fatalf("MarshalProviderArtifacts: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}

	registry := mustDefaultRegistry(t)
	_, err = registry.Prepare([]Source{{
		PackageID: "nervus.pkgmanagerd",
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustPlatform,
		Signers: SignerEvidence{
			Roles: []string{rolePlatformRelease},
			VerifiedSigners: []VerifiedSigner{{
				Role: rolePlatformRelease, KeyID: "platform-release-key",
			}},
		},
		Exports: []ExportBinding{{
			ComponentID: "main", InterfaceID: InterfacePackageManager,
		}},
		Artifacts: artifacts,
	}})
	if err == nil {
		t.Fatal("unexpected catalog result; provider sameInterfaceContract")
	}
}
