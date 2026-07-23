package pkgregistry

import (
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

// 只有【只读系统镜像】来源的、已验证为 OEM/Platform 的签名才能拿到非
// Ordinary 的信任——判定标准是"来自系统镜像"，不是单看签名字段本身
func TestArbitrate_SystemImageWithVerifiedPlatformTrust(t *testing.T) {
	d := Arbitrate(Manifest{}, SourceSystemImage, identity.TrustPlatform, []string{"perm.a"})
	if d.Trust != identity.TrustPlatform {
		t.Fatalf("Trust = %v, want TrustPlatform", d.Trust)
	}
}

func TestArbitrate_SystemImageWithVerifiedOEMTrust(t *testing.T) {
	d := Arbitrate(Manifest{}, SourceSystemImage, identity.TrustOEM, nil)
	if d.Trust != identity.TrustOEM {
		t.Fatalf("Trust = %v, want TrustOEM", d.Trust)
	}
}

// 一份 OEM/Platform 签名的 manifest 如果走的是动态安装路径，依然只能拿
// Ordinary——判定标准是来源，不是签名本身，防止"自称 system"式的提权
func TestArbitrate_DynamicInstallAlwaysOrdinary(t *testing.T) {
	cases := []identity.TrustProfile{
		identity.TrustUnspecified, identity.TrustOrdinary, identity.TrustOEM, identity.TrustPlatform,
	}
	for _, verified := range cases {
		d := Arbitrate(Manifest{}, SourceDynamicInstall, verified, nil)
		if d.Trust != identity.TrustOrdinary {
			t.Errorf("verifiedTrust=%v: Trust = %v, want TrustOrdinary", verified, d.Trust)
		}
	}
}

// 未验证（TrustUnspecified）或验证失败时，即便来源是系统镜像也不能给
// 高信任——没有验证结果就不能发放特权
func TestArbitrate_SystemImageWithUnverifiedTrustFallsBackToOrdinary(t *testing.T) {
	d := Arbitrate(Manifest{}, SourceSystemImage, identity.TrustUnspecified, nil)
	if d.Trust != identity.TrustOrdinary {
		t.Fatalf("Trust = %v, want TrustOrdinary", d.Trust)
	}
}

func TestArbitrate_GrantedPermsIsPassthroughCopy(t *testing.T) {
	requested := []string{"perm.a", "perm.b"}
	d := Arbitrate(Manifest{}, SourceSystemImage, identity.TrustPlatform, requested)
	if len(d.GrantedPerms) != 2 {
		t.Fatalf("GrantedPerms = %v", d.GrantedPerms)
	}
	// 必须是拷贝，不能与调用方的切片共享底层数组
	d.GrantedPerms[0] = "mutated"
	if requested[0] == "mutated" {
		t.Fatal("GrantedPerms 与调用方切片共享了底层数组")
	}
}
