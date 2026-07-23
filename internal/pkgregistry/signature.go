// 见 doc.go 的包说明
//
// 本文件是签名验证的接缝。签名根、算法与信任链格式（/usr/share/nervus/trust/
// 的具体内容）目前没有任何文档拍板，参照 internal/ipc 的 verifyComponent
// 先例：先给一个显式的 stub，绝不假装验证通过
package pkgregistry

import (
	"errors"

	"github.com/nervus-os/nervud/internal/identity"
)

// ErrSignatureVerificationUnimplemented 签名验证尚未实现
//
// 调用方必须把它与“签名验证已执行但失败”区分开记审计——前者是能力缺口
// （呼应 ipc.auditUnsupported 的分类思路），后者才是真正的协议违规/攻击线索。
// 但两者在裁决结果上完全一致：都是 fail-closed，都不发放非 Ordinary 信任
var ErrSignatureVerificationUnimplemented = errors.New("pkgregistry: signature verification not implemented")

// verifySignature 校验 manifestBytes 与其分离签名 sigBlock，返回签名者身份
// 与该签名对应的最大信任 profile
//
// manifestBytes 必须是签名所覆盖的原始字节，不能用已解析的 Manifest 结构体
// 重新序列化回去比较——签名验证必须针对字节，不能针对“我们理解出的语义”
func verifySignature(_ []byte, _ []byte) (signer string, trust identity.TrustProfile, err error) {
	return "", identity.TrustUnspecified, ErrSignatureVerificationUnimplemented
}
