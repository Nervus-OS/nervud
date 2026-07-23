// 见 doc.go 的包说明
//
// 本文件是最终安装裁决的核心规则：由安装来源与已验证的签名信任，
// 决定这个 Package 最终能拿到的信任 profile（架构 §7）
package pkgregistry

import "github.com/nervus-os/nervud/internal/identity"

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

// Decision 是一次安装裁决的结果
type Decision struct {
	Trust identity.TrustProfile

	// GrantedPerms 是 manifest 请求权限的直通记录，只反映"申请了什么"，
	// 不代表已经放行——真正的"请求 ∩ 已注册权限 ∩ trust 门槛"交集运算由
	// internal/permission.Intersect 完成（见 install.go 的 Install()，它在
	// Arbitrate 之后紧接着调用 m.perm.Intersect(manifest.Permissions,
	// decision.Trust)，结果写进 Entry.GrantedPermissions，不是这个字段）。
	// 真正的运行期执法在 permission.Registry.Allowed（架构 §9 最后一步）
	GrantedPerms []string
}

// Arbitrate 是最终安装裁决：manifest 必须已经通过独立复核（签名+digest，
// 见 signature.go/digest.go），本函数只回答“这个来源 + 这份已验证信任，
// 最终该给多高的 profile”
//
// 架构 §7 的硬规则：只有【只读系统镜像里】平台/OEM 签名的 Package 才有资格
// 获得非 Ordinary 的信任；判定标准是“来自只读系统镜像”，不是单看签名本身——
// 一份 OEM 签名的 manifest 如果走的是动态安装路径，依然只能拿 Ordinary。
// manifest 不能通过自称 system 或者随便一个签名就完成提权
func Arbitrate(_ Manifest, src Source, verifiedTrust identity.TrustProfile, requestedPerms []string) Decision {
	trust := identity.TrustOrdinary
	if src == SourceSystemImage && verifiedTrust.Valid() && verifiedTrust != identity.TrustOrdinary {
		trust = verifiedTrust
	}

	granted := make([]string, len(requestedPerms))
	copy(granted, requestedPerms)

	return Decision{Trust: trust, GrantedPerms: granted}
}
