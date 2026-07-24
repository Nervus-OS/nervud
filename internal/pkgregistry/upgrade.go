// 见 doc.go 的包说明
//
// 本文件是升级裁决（应用层架构决策 §2.6/§4.1）。
//
// 重要性排序（§2.6）：
//  1. 签名连续性（lineage 后继）—— 防身份劫持与数据窃取。UID 与私有数据目录都
//     按 package_id 分配，没有连续性检查，任何人做一个同 package_id 的包用自己的
//     密钥签、装上去，就继承了原包的 UID、数据与已授予权限。【devmode 也不放宽】。
//  2. 防降级（version_code 单调）—— 防塞回有已知漏洞的旧版本。devmode 可放宽。
//
// 全新安装（含卸载后重装）不走这里：数据没了、UID 是新的，没有任何东西可被
// 继承，谈不上劫持或降级，任意 version_code / 任意签名者都接受（§4.1）。
package pkgregistry

import (
	"errors"
	"fmt"
)

var (
	// ErrDowngradeNotAllowed 升级包的 version_code 低于已装版本（devmode 可放宽）
	ErrDowngradeNotAllowed = errors.New("pkgregistry: downgrade not allowed")

	// ErrSignerMismatch 升级包的签名血统不是已装版本血统的后继——这是身份劫持
	// 的信号，绝不放宽（devmode 也不行）
	ErrSignerMismatch = errors.New("pkgregistry: upgrade signer is not a lineage successor of the installed package")

	// ErrOEMCountersignRequired 设备策略要求 OEM 副署，但包缺少有效的 OEM 签名
	ErrOEMCountersignRequired = errors.New("pkgregistry: device policy requires an OEM countersignature")
)

// checkUpgrade 在“已安装同 package_id”时执行的升级裁决
//
// prev 是已装版本的持久化记账；signers 是新包的多角色验签结论；dev 是当前 devmode
func checkUpgrade(prev registryState, m Manifest, signers SignerSet, dev DevMode) error {
	// ---- 1. 防降级（次要目的；devmode 可放宽）----
	switch {
	case m.VersionCode > prev.VersionCode:
		// 正常升级
	case m.VersionCode == prev.VersionCode:
		// 同版本重装（修复损坏安装），允许（§4.1）
	default:
		if !dev.AllowDowngrade {
			return fmt.Errorf("%w: %d < installed %d", ErrDowngradeNotAllowed, m.VersionCode, prev.VersionCode)
		}
	}

	// ---- 2. 签名连续性（主要目的：防身份劫持；绝不放宽）----
	if len(prev.LineageKeyIDs) == 0 {
		// 上一版是 unverified 安装（devmode 放行、无身份锚点）：没有可强制的连续性。
		// 允许——反正原本也没有身份保证可被劫持
		return nil
	}
	if signers.Dev == nil {
		// 上一版有身份锚点，却要用一个没有 developer 签名的包顶替它、继承它的
		// UID 与数据目录 —— 这正是 §2.6 要防的劫持
		return fmt.Errorf("%w: installed package is signed but replacement carries no developer identity", ErrSignerMismatch)
	}
	if signers.Dev.RootKeyID != prev.LineageRootKeyID {
		return fmt.Errorf("%w: root %q != installed root %q",
			ErrSignerMismatch, signers.Dev.RootKeyID, prev.LineageRootKeyID)
	}
	// 是后继，不是分叉：新血统必须至少和旧的一样长，且前 len(prev) 个节点逐一相等
	if signers.Dev.LineageLen < len(prev.LineageKeyIDs) {
		return fmt.Errorf("%w: lineage shrank from %d to %d",
			ErrSignerMismatch, len(prev.LineageKeyIDs), signers.Dev.LineageLen)
	}
	for i, id := range prev.LineageKeyIDs {
		if signers.Dev.KeyIDs[i] != id {
			return fmt.Errorf("%w: lineage diverges at node %d", ErrSignerMismatch, i)
		}
	}
	return nil
}
