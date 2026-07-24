// 本文件是安装时权限裁决的核心（ 统一验证流程第 5 步）：
// 裁决只保留请求权限、已注册权限与 trust 门槛的交集
package permission

import "github.com/nervus-os/nervud/internal/identity"

// V1GrantAll 是 v1 交付期的权限总开关。
//
// 打开后两件事同时生效：
//   - 安装时：manifest 申请什么就授予什么，不查 Catalog、不看 trust 门槛、
//     不看 RequireSignerRole（见 Intersect）
//   - 运行期：GrantUser（危险）权限不再要求用户确认状态 == Granted（见 Registry.Allowed）
//
// 为什么是一个常量而不是 flag：它放宽的是安全裁决，绝不能变成运行期可开关的
// 东西——生产二进制里不该存在一个「把权限系统关掉」的命令行参数。要恢复执法
// 就把它改回 false 重新编译，改动点在 grep V1GrantAll 能找全的两处。
//
// 恢复执法时要一并处理的事：权限 ID 的正式命名空间与取值表仍未冻结
// （见 catalog.go 的 DefaultCatalog），届时 Catalog 必须先补全，否则 Intersect
// 会把所有未登记的权限一律拒掉。
//
// 注意本开关【不】放宽「必须在 manifest 里声明」这一条：没申请过的权限
// 仍然进不了 install-set，Allowed 照样返回 false。
const V1GrantAll = true

// Intersect 计算一个 Package 实际能拿到的权限集合
//
// requested 来自 manifest.Permissions，trust 来自 pkgregistry.Arbitrate 已经
// 裁决出的最终 trust profile（不是签名验证的 verifiedTrust - 一份 OEM 签名走
// 动态安装路径时，Arbitrate 已经把它按 Ordinary 处理，Intersect 只认 Arbitrate
// 的结论，不重新判断来源）
//
// 未登记在 Catalog 里的权限 ID 一律不予授予（fail closed）：一个 manifest
// 申请了系统不认识的权限字符串，视为申请失败而不是"忽略未知项、放行其余" -
// 静默忽略等于允许拼写错误或未来版本的权限 ID 在旧 build 上被默默丢弃却不报错
//
// denied 一并返回而不是只返回 granted：审计需要知道"申请了但没拿到"这件事
// 本身，日后 Policy 层（v2，用户确认危险权限）接入时也需要先知道 denied
// 集合里哪些是"trust 不够"哪些是"根本没听说过这个权限 ID"
//
// 本函数只做机械裁决，不涉及任何运行时用户交互或阻塞调用 - v2 Policy 的
// "用户确认"不在这里实现
// signerRoles 是该包已验证签名里出现的角色字符串集合（如 "developer"、
// "platform-release"）。用于 RequireSignerRole 裁决：某些最危险的权限只给特定角色
// 签的包，比单纯 trust 等级更细。空集表示无可用角色信息，
// 带 RequireSignerRole 的权限一律拒
func Intersect(requested []string, cat Catalog, trust identity.TrustProfile, signerRoles []string) (granted, denied []string) {
	// v1：申请即授予。放在最前面短路，连 Catalog 查表都跳过——否则未登记的
	// 权限 ID（OEM 自定义权限、还没进 DefaultCatalog 的标准权限）仍会被拒，
	// 达不到「系统服务在描述文件里声明、用户软件申请就能用」的效果。
	if V1GrantAll {
		return append([]string(nil), requested...), nil
	}

	roleSet := make(map[string]struct{}, len(signerRoles))
	for _, r := range signerRoles {
		roleSet[r] = struct{}{}
	}
	for _, id := range requested {
		entry, ok := cat.Lookup(id)
		if !ok {
			denied = append(denied, id)
			continue
		}
		// identity.TrustProfile 的常量声明顺序本身就是特权递增序
		// （Unspecified < Ordinary < OEM < Platform），数值比较即门槛比较
		if trust < entry.MinTrust {
			denied = append(denied, id)
			continue
		}
		// RequireSignerRole：只有该角色签的包才能拿。角色缺失即拒
		if entry.RequireSignerRole != "" {
			if _, ok := roleSet[entry.RequireSignerRole]; !ok {
				denied = append(denied, id)
				continue
			}
		}
		granted = append(granted, id)
	}
	return granted, denied
}
