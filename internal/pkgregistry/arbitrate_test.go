package pkgregistry

import (
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

func TestArbitrate_SystemImageWithVerifiedPlatformTrust(t *testing.T) {
	trust := Arbitrate(SourceSystemImage, SignerSet{Trust: identity.TrustPlatform})
	if trust != identity.TrustPlatform {
		t.Fatalf("Trust = %v, want TrustPlatform", trust)
	}
}

func TestArbitrate_SystemImageWithVerifiedOEMTrust(t *testing.T) {
	trust := Arbitrate(SourceSystemImage, SignerSet{Trust: identity.TrustOEM})
	if trust != identity.TrustOEM {
		t.Fatalf("Trust = %v, want TrustOEM", trust)
	}
}

func TestArbitrate_DynamicInstallAlwaysOrdinary(t *testing.T) {
	cases := []identity.TrustProfile{
		identity.TrustUnspecified, identity.TrustOrdinary, identity.TrustOEM, identity.TrustPlatform,
	}
	for _, verified := range cases {
		trust := Arbitrate(SourceDynamicInstall, SignerSet{Trust: verified})
		if trust != identity.TrustOrdinary {
			t.Errorf("verifiedTrust=%v: Trust = %v, want TrustOrdinary", verified, trust)
		}
	}
}

func TestArbitrate_SystemImageWithUnverifiedTrustFallsBackToOrdinary(t *testing.T) {
	trust := Arbitrate(SourceSystemImage, SignerSet{Trust: identity.TrustUnspecified})
	if trust != identity.TrustOrdinary {
		t.Fatalf("Trust = %v, want TrustOrdinary", trust)
	}
}
