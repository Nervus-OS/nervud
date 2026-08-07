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

// perm.pkg.admin 取代了内核里写死的「哪个 Package ID 能连管理通道」。
// 这条断言确认它真的能被授予——否则装包链路会静默断掉，症状是
// pkgmanagerd 起来了但连不上管理通道。
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
		t.Fatalf("platform-release 系统镜像包拿不到 %s: granted=%v denied=%v",
			permPackageAdmin, granted, denied)
	}
}

// 三道门必须各自独立生效。任何一道松了，一个不该有装包权的包就能连上
// 管理通道——那条通道能装任意可执行文件进系统。
func TestPackageAdmin_DeniedWithoutFullAuthority(t *testing.T) {
	tests := []struct {
		name    string
		source  catalog.SourceKind
		trust   identity.TrustProfile
		signers catalog.SignerEvidence
	}{
		{
			// GRANT_MODE_SYSTEM_ONLY：动态安装包一律拒
			name:    "动态安装",
			source:  catalog.SourceKindDynamicInstall,
			trust:   identity.TrustOrdinary,
			signers: platformReleaseSigners(),
		},
		{
			// MinimumTrust=PLATFORM：开发构建里降级到 Ordinary 的包拿不到
			name:    "系统镜像但只有 Ordinary 信任",
			source:  catalog.SourceKindSystemImage,
			trust:   identity.TrustOrdinary,
			signers: platformReleaseSigners(),
		},
		{
			// OEM 也不够：装包是平台职责
			name:    "系统镜像但只有 OEM 信任",
			source:  catalog.SourceKindSystemImage,
			trust:   identity.TrustOEM,
			signers: platformReleaseSigners(),
		},
		{
			// RequiredSignerRole=platform-release：信任够但签名角色不对
			name:   "Platform 信任但非 platform-release 签名",
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
			name:    "无任何签名证据",
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
				t.Fatalf("%s 竟然拿到了 %s", tc.name, permPackageAdmin)
			}
			if !slices.Contains(denied, permPackageAdmin) {
				t.Fatalf("denied 里没有 %s: %v", permPackageAdmin, denied)
			}
		})
	}
}
