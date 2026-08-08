package permission

import (
	"slices"
	"testing"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

const permPackageAdmin = "perm.pkg.admin"

func platformReleaseSigners() catalog.SignerEvidence {
	return catalog.SignerEvidence{
		Roles: []string{"platform-release"},
		VerifiedSigners: []catalog.VerifiedSigner{{
			Role: "platform-release", KeyID: "platform-release-key",
		}},
	}
}

func TestPackageAdmin_GrantedToPlatformReleaseSystemImage(t *testing.T) {
	r := NewDefaultRegistry()
	granted, denied := r.IntersectAt(
		r.definitions.Current(),
		[]string{permPackageAdmin},
		catalog.SourceKindSystemImage,
		identity.TrustPlatform,
		platformReleaseSigners(),
	)
	if !slices.Contains(granted, permPackageAdmin) {
		t.Fatalf("unexpected permission result; platform-release %s: granted=%v denied=%v",
			permPackageAdmin, granted, denied)
	}
}

func TestPackageAdmin_DeniedWithoutFullAuthority(t *testing.T) {
	tests := []struct {
		name    string
		source  catalog.SourceKind
		trust   identity.TrustProfile
		signers catalog.SignerEvidence
	}{
		{

			name:    "permission test value 724bc2",
			source:  catalog.SourceKindDynamicInstall,
			trust:   identity.TrustOrdinary,
			signers: platformReleaseSigners(),
		},
		{

			name:    "permission test value 4f4ca2; Ordinary",
			source:  catalog.SourceKindSystemImage,
			trust:   identity.TrustOrdinary,
			signers: platformReleaseSigners(),
		},
		{

			name:    "permission test value df674f; OEM",
			source:  catalog.SourceKindSystemImage,
			trust:   identity.TrustOEM,
			signers: platformReleaseSigners(),
		},
		{

			name:   "permission test value 54d9b8; Platform platform-release",
			source: catalog.SourceKindSystemImage,
			trust:  identity.TrustPlatform,
			signers: catalog.SignerEvidence{
				Roles: []string{"oem-service"},
				VerifiedSigners: []catalog.VerifiedSigner{{
					Role: "oem-service", KeyID: "oem-key",
				}},
			},
		},
		{
			name:    "permission test value 572ba9",
			source:  catalog.SourceKindSystemImage,
			trust:   identity.TrustPlatform,
			signers: catalog.SignerEvidence{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewDefaultRegistry()
			granted, denied := r.IntersectAt(
				r.definitions.Current(),
				[]string{permPackageAdmin},
				tc.source, tc.trust, tc.signers,
			)
			if slices.Contains(granted, permPackageAdmin) {
				t.Fatalf("unexpected permission result; value = %s %s", tc.name, permPackageAdmin)
			}
			if !slices.Contains(denied, permPackageAdmin) {
				t.Fatalf("unexpected permission result; denied %s: %v", permPackageAdmin, denied)
			}
		})
	}
}
