package pkgregistry

import (
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

// 豁免运行期同意的判据是【随只读系统镜像发布】且【受平台信任】, 两个都要.
//
// 只看 Source: 一个塞进镜像目录的低信任包就能蒙混过关.
// 只看 Trust: 一个动态安装的平台签名包也会免掉询问 —— 而"装机时用户已经
// 接受了它"这条理由只对随镜像发布的那批成立.
func TestProjectGrants_ConsentExemptRequiresBothSourceAndTrust(t *testing.T) {
	cases := []struct {
		name   string
		source Source
		trust  identity.TrustProfile
		want   bool
	}{
		{"系统镜像+平台信任", SourceSystemImage, identity.TrustPlatform, true},
		{"系统镜像+OEM信任", SourceSystemImage, identity.TrustOEM, false},
		{"系统镜像+普通信任", SourceSystemImage, identity.TrustOrdinary, false},
		{"动态安装+平台信任", SourceDynamicInstall, identity.TrustPlatform, false},
		{"动态安装+普通信任", SourceDynamicInstall, identity.TrustOrdinary, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entry := Entry{
				Manifest:           Manifest{PackageID: "com.example.app"},
				Source:             c.source,
				Trust:              c.trust,
				GrantedPermissions: []string{"perm.storage.user"},
			}
			got := projectGrants([]Entry{entry})
			if len(got) != 1 {
				t.Fatalf("投影数 = %d, want 1", len(got))
			}
			if got[0].ConsentExempt != c.want {
				t.Errorf("ConsentExempt = %v, want %v", got[0].ConsentExempt, c.want)
			}
			// 豁免与否都不该改动安装期集合
			if len(got[0].Permissions) != 1 {
				t.Errorf("权限集合被改动了: %v", got[0].Permissions)
			}
		})
	}
}
