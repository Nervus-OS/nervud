// 见 doc.go 的包说明
//
// 本文件是最终安装裁决的核心规则：由安装来源与已验证的多角色签名，决定这个
// Package 最终能拿到的信任 profile（应用层架构决策 §2.2）
package pkgregistry

import (
	"errors"

	"github.com/nervus-os/nervud/internal/identity"
)

// ErrInvalidSource 一次 Install 事务的 Source 不是合法来源（漏填/零值）。
// 准入检查（developer 必签、OEM 副署）只对已知来源触发，未知来源必须整体拒绝，
// 否则会绕过全部准入形成幽灵包（应用层架构决策 §4）
var ErrInvalidSource = errors.New("pkgregistry: install transaction has invalid source")

// Source 是 manifest 的来源，决定了它有没有资格拿到非 Ordinary 的信任
type Source int

const (
	// SourceUnspecified 零值即无效，防止未初始化的调用被当成合法来源
	SourceUnspecified Source = iota

	// SourceSystemImage 只读系统镜像内置 Package（/usr/lib/nervus/system-packages/）
	SourceSystemImage

	// SourceDynamicInstall 运行期动态安装（pkgmanagerd 的 staging 流程）
	SourceDynamicInstall
)

func (s Source) String() string {
	switch s {
	case SourceSystemImage:
		return "system-image"
	case SourceDynamicInstall:
		return "dynamic-install"
	default:
		return "unspecified"
	}
}

// Arbitrate 是最终信任裁决：来源 + 多角色验签结论 -> 最终 TrustProfile
//
// 硬规则（应用层架构决策 §2.2 红线 1）：只有来自【只读系统镜像】的包才有资格
// 获得非 Ordinary 的信任。一份带 platform/oem 签名的 manifest 如果走的是动态
// 安装路径，依然只能拿 Ordinary——判定标准是”来自系统镜像”，不是签名本身。
// manifest 不能通过带一个高角色签名就在动态安装路径上完成提权
//
// SignerSet.Trust 已经是 VerifySignature 根据多角色签名算出的最高信任（平台根/OEM
// 根背书的密钥 → Platform/OEM，developer 自签 → Ordinary），本函数只负责来源门槛：
// 动态安装一律降为 Ordinary，系统镜像透传 SignerSet.Trust（但 Unspecified 归一为 Ordinary）
//
// 权限的”请求 ∩ 已注册 ∩ trust 门槛”交集运算在 permission.Intersect 完成
// （见 install.go），不在这里；本函数只回答”该给多高的信任”
func Arbitrate(src Source, signers SignerSet) identity.TrustProfile {
	if src != SourceSystemImage {
		return identity.TrustOrdinary
	}
	// 系统镜像来源：透传 VerifySignature 的结论，但 Unspecified（未验证/验证失败）
	// 归一为 Ordinary——没有验证结果就不能发放特权
	if signers.Trust == identity.TrustUnspecified {
		return identity.TrustOrdinary
	}
	return signers.Trust
}
