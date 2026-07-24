package pkgregistry

import (
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

// 只有【只读系统镜像】来源的包才能拿到非 Ordinary 的信任——判定标准是来源，
// 不是单看签名本身。签名角色由 SignerSet.Trust 携带（应用层架构决策 §2.2）
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

// 一份 OEM/Platform 签名的 manifest 如果走的是动态安装路径，依然只能拿
// Ordinary——判定标准是来源，不是签名本身，防止"自称 system"式的提权
// （架构决策红线 1：只有来自只读系统镜像的包才有资格拿非 Ordinary）
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

// 未验证（TrustUnspecified）或验证失败时，即便来源是系统镜像也只能拿 Ordinary
// ——没有验证结果就不能发放特权
func TestArbitrate_SystemImageWithUnverifiedTrustFallsBackToOrdinary(t *testing.T) {
	trust := Arbitrate(SourceSystemImage, SignerSet{Trust: identity.TrustUnspecified})
	if trust != identity.TrustOrdinary {
		t.Fatalf("Trust = %v, want TrustOrdinary", trust)
	}
}
