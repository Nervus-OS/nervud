// 见 doc.go 的包说明
//
// 本文件是安装时权限裁决的核心（架构 §9 统一验证流程第 5 步）：
// "请求权限 ∩ 已注册权限 ∩ trust 门槛"
package permission

import "github.com/nervus-os/nervud/internal/identity"

// Intersect 计算一个 Package 实际能拿到的权限集合
//
// requested 来自 manifest.Permissions，trust 来自 pkgregistry.Arbitrate 已经
// 裁决出的最终 trust profile（不是签名验证的 verifiedTrust——一份 OEM 签名走
// 动态安装路径时，Arbitrate 已经把它按 Ordinary 处理，Intersect 只认 Arbitrate
// 的结论，不重新判断来源）
//
// 未登记在 Catalog 里的权限 ID 一律不予授予（fail closed）：一个 manifest
// 申请了系统不认识的权限字符串，视为申请失败而不是"忽略未知项、放行其余"——
// 静默忽略等于允许拼写错误或未来版本的权限 ID 在旧 build 上被默默丢弃却不报错
//
// denied 一并返回而不是只返回 granted：审计需要知道"申请了但没拿到"这件事
// 本身，日后 Policy 层（v2，用户确认危险权限）接入时也需要先知道 denied
// 集合里哪些是"trust 不够"哪些是"根本没听说过这个权限 ID"
//
// 本函数只做机械裁决，不涉及任何运行时用户交互或阻塞调用——v2 Policy 的
// "用户确认"不在这里实现
func Intersect(requested []string, cat Catalog, trust identity.TrustProfile) (granted, denied []string) {
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
		granted = append(granted, id)
	}
	return granted, denied
}
