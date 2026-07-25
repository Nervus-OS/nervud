// 本文件给【系统镜像来源】的 Package 做权限裁决。
//
// # 为什么系统包需要单独一条裁决路径
//
// 动态安装的包在 Install 当时就调 permission.Intersect 算出 GrantedPermissions，
// 并随记账文件持久化；重启只读回，不重新裁决（见 install.go 与 scan.go 的
// scanDynamicInstalls）。
//
// 系统镜像包不走 Install —— 它们由 scanSystemImage 直接构造 Entry，那条路径
// 从不调 Intersect。结果是 GrantedPermissions 恒为 nil，于是【每一个系统服务
// 都拿不到任何权限】：
//
//	pkgmanagerd    注册 endpoint  → missing permission perm.service.register
//	safetyrecoveryd 解析 endpoint  → lacks required permission perm.safety.rearm
//
// 两条都是真实撞到的。这与 provision.go 记的是同一类根因：系统镜像扫描路径
// 比动态安装路径少做了几步收尾，而少的那几步恰好都是「包能不能真的跑起来」。
//
// # 为什么不放进 Scan
//
// Scan 是纯函数，只吃路径与 TrustStore，不持有 PermissionArbiter —— 它被
// 测试与诊断直接调用，把权限注册表拖进去会让它不再可独立求值。裁决因此留在
// Module.Start，与 provisionAll 并列：都是「扫描结果落地成可运行状态」的收尾。
package pkgregistry

import (
	"context"
	"fmt"

	"github.com/nervus-os/nervud/internal/audit"
)

// arbitrateSystemGrants 就地为系统镜像来源的 Entry 填 GrantedPermissions。
//
// 只动 SourceSystemImage：动态安装的 Entry 已经带着 Install 时裁决好的结果从
// 记账文件读回来了，重算会用【当前】的 trust 与签名角色覆盖【安装当时】的裁决，
// 那是一次静默的权限漂移。
//
// 返回被授予了至少一项权限的包数量，供调用方记日志。
func (m *Module) arbitrateSystemGrants(ctx context.Context, entries []Entry) int {
	n := 0
	for i := range entries {
		e := &entries[i]
		if e.Source != SourceSystemImage {
			continue
		}
		if len(e.Manifest.Permissions) == 0 {
			continue
		}
		granted, denied := m.perm.Intersect(e.Manifest.Permissions, e.Trust, e.SignerRoles)
		e.GrantedPermissions = granted
		if len(denied) > 0 {
			m.aud.Record(ctx, audit.Event{
				Action: "pkgregistry.Intersect", Subject: e.Manifest.PackageID,
				Denied: true, Detail: fmt.Sprintf("%v", denied),
			})
			if m.log != nil {
				// WARN 而不是 ERROR：包照常装载，只是它请求的某些权限没拿到。
				// 拿不到的后果由它自己在运行期撞见（endpoint 注册/解析被拒）。
				m.log.Warn("pkgregistry: system package permissions denied",
					"package_id", e.Manifest.PackageID, "denied", denied, "trust", e.Trust.String())
			}
		}
		if len(granted) > 0 {
			n++
		}
	}
	return n
}
