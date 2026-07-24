// 本文件是 manifest.sig 的 wire 格式：多角色并列签名
// 与密钥血统（lineage）的数据模型与结构性校验。这里只解析与查结构，不做任何
// 密码学验证 - 真正的验签、信任根解析与 lineage 链式核对在 signature.go
package pkgregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// sigBlockFormatV1 是本版本认识的唯一 manifest.sig 顶层格式号
	sigBlockFormatV1 = 1
	// lineageFormatV1 是本版本认识的唯一 lineage 格式号
	lineageFormatV1 = 1

	// maxSignatures 一份 manifest.sig 里的签名条目上限
	maxSignatures = 8
	// maxLineageNodes 一条血统链的节点上限，防超长链打爆 CPU
	maxLineageNodes = 16
)

// 签名域分隔前缀：防跨协议签名重用
//
//   - manifestSigDomain 覆盖 manifest.json 原始字节
//   - lineageSigDomain 覆盖 被授权接替的下一节点 的 key_id||key
//   - lineageBindDomain 把整条血统绑进 developer 签名（见 developerSignMessage）：
//     否则 developer 只签 manifest 原始字节，血统就是可替换的 - 中间人能给一份
//     真实 B 签名的包换上任意 A_evil -> B 血统、把 root 毒化成自己的密钥，之后合法
//     B 升级因 root 不同被拒，形成持久升级 DoS / 身份劫持
//
// 这三个常量是签名与验签双方必须逐字节一致的协议真源，改动即破坏兼容。
// 用 const string（而非 var []byte）：既是真正的常量、不可被运行期改写，也避开
// gochecknoglobals。用作 append([]byte{}, domain...) 时 Go 允许把 string 追加进 []byte
const (
	manifestSigDomain = "nervus-pkg-manifest-v1\x00"
	lineageSigDomain  = "nervus-lineage-v1\x00"
	lineageBindDomain = "nervus-lineage-bind-v1\x00"
)

// SignerRole 是签名者的角色，决定它能证明的最高信任
//
// 角色按权限影响面而非组件类型划分：组件是 app 还是 service 由 manifest 的
// component.type 表达，用密钥再表达一遍就是两个真相源
type SignerRole string

const (
	RoleDeveloper         SignerRole = "developer"          // 开发者自签
	RolePlatformRelease   SignerRole = "platform-release"   // 平台：nervud + 核心系统服务
	RolePlatformSystemApp SignerRole = "platform-systemapp" // 平台：系统软件
	RoleOEMService        SignerRole = "oem-service"        // OEM：硬件 Provider Service
	RoleOEMApp            SignerRole = "oem-app"            // OEM：系统软件
	// RoleOEMTrustSoftware OEM 为普通软件/服务背书（副署）；仍只发 Ordinary 信任，
	// 作用是OEM 认可这个第三方包可以装在我的设备上
	RoleOEMTrustSoftware SignerRole = "oem-trust-software"
)

func (r SignerRole) valid() bool {
	switch r {
	case RoleDeveloper, RolePlatformRelease, RolePlatformSystemApp,
		RoleOEMService, RoleOEMApp, RoleOEMTrustSoftware:
		return true
	default:
		return false
	}
}

// SigAlg 是签名算法。v1 只允许 ed25519；保留字段是为了将来的算法敏捷性，
// 未知取值一律拒绝，不做尽量兼容
type SigAlg string

const SigAlgEd25519 SigAlg = "ed25519"

var (
	// ErrSigBlockMalformed manifest.sig 结构不合法（格式号、空字段、条目数超限等）
	ErrSigBlockMalformed = errors.New("pkgregistry: malformed signature block")
	// ErrUnknownSigAlg 签名条目使用了未知算法
	ErrUnknownSigAlg = errors.New("pkgregistry: unknown signature algorithm")
	// ErrUnknownSignerRole 签名条目使用了未知角色
	ErrUnknownSignerRole = errors.New("pkgregistry: unknown signer role")
	// ErrDuplicateKeyID 同一份 manifest.sig 里重复出现同一个 key_id
	ErrDuplicateKeyID = errors.New("pkgregistry: duplicate key_id in signature block")
	// ErrLineageMalformed lineage 结构不合法
	ErrLineageMalformed = errors.New("pkgregistry: malformed lineage")
)

// Signature 是 manifest.sig 里的一条签名
type Signature struct {
	Role  SignerRole `json:"role"`
	Alg   SigAlg     `json:"alg"`
	KeyID string     `json:"key_id"`
	// Key 是 base64 raw pubkey。developer 角色必须内嵌（自签）；其余角色可选，
	// 若内嵌则必须与信任库里 key_id 对应的公钥逐字节一致（在 signature.go 核对）
	Key string `json:"key,omitempty"`
	Sig string `json:"sig"`
}

// LineageNode 是一条血统链上的一个节点
type LineageNode struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
	// SignedByPrev = 用 nodes[i-1] 私钥签 (lineageSigDomain || key_id || key)。
	// 首节点无此字段；其余节点必填
	SignedByPrev string `json:"signed_by_prev,omitempty"`
}

// Lineage 是密钥血统链：nodes[0] 是根，最后一个节点是当前有效签名密钥
type Lineage struct {
	Format int           `json:"format"`
	Nodes  []LineageNode `json:"nodes"`
}

// SignatureBlock 是 manifest.sig 的解析结果
type SignatureBlock struct {
	Format     int         `json:"format"`
	Signatures []Signature `json:"signatures"`
	Lineage    *Lineage    `json:"lineage,omitempty"`
}

// ParseSignatureBlock 反序列化 manifest.sig 并做结构性校验
//
// 只校验形状是否合法：格式号、空字段、条目数上限、key_id 去重、算法/角色可识别、
// lineage 节点上限与首节点无 signed_by_prev。密码学验签在 signature.go
func ParseSignatureBlock(data []byte) (SignatureBlock, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var sb SignatureBlock
	if err := dec.Decode(&sb); err != nil {
		return SignatureBlock{}, fmt.Errorf("pkgregistry: decode signature block: %w", err)
	}
	if err := sb.validate(); err != nil {
		return SignatureBlock{}, err
	}
	return sb, nil
}

func (sb SignatureBlock) validate() error {
	if sb.Format != sigBlockFormatV1 {
		return fmt.Errorf("%w: format %d", ErrSigBlockMalformed, sb.Format)
	}
	if len(sb.Signatures) == 0 {
		return fmt.Errorf("%w: no signatures", ErrSigBlockMalformed)
	}
	if len(sb.Signatures) > maxSignatures {
		return fmt.Errorf("%w: %d signatures exceed cap %d", ErrSigBlockMalformed, len(sb.Signatures), maxSignatures)
	}

	seenKeyID := make(map[string]struct{}, len(sb.Signatures))
	for _, s := range sb.Signatures {
		if !s.Role.valid() {
			return fmt.Errorf("%w: %q", ErrUnknownSignerRole, s.Role)
		}
		if s.Alg != SigAlgEd25519 {
			return fmt.Errorf("%w: %q", ErrUnknownSigAlg, s.Alg)
		}
		if s.KeyID == "" || s.Sig == "" {
			return fmt.Errorf("%w: signature with empty key_id or sig", ErrSigBlockMalformed)
		}
		if s.Role == RoleDeveloper && s.Key == "" {
			return fmt.Errorf("%w: developer signature must embed its public key", ErrSigBlockMalformed)
		}
		if _, dup := seenKeyID[s.KeyID]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateKeyID, s.KeyID)
		}
		seenKeyID[s.KeyID] = struct{}{}
	}

	if sb.Lineage != nil {
		if err := sb.Lineage.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (l Lineage) validate() error {
	if l.Format != lineageFormatV1 {
		return fmt.Errorf("%w: format %d", ErrLineageMalformed, l.Format)
	}
	if len(l.Nodes) == 0 {
		return fmt.Errorf("%w: no nodes", ErrLineageMalformed)
	}
	if len(l.Nodes) > maxLineageNodes {
		return fmt.Errorf("%w: %d nodes exceed cap %d", ErrLineageMalformed, len(l.Nodes), maxLineageNodes)
	}
	for i, n := range l.Nodes {
		if n.KeyID == "" || n.Key == "" {
			return fmt.Errorf("%w: node %d has empty key_id or key", ErrLineageMalformed, i)
		}
		if i == 0 && n.SignedByPrev != "" {
			return fmt.Errorf("%w: root node must not carry signed_by_prev", ErrLineageMalformed)
		}
		if i > 0 && n.SignedByPrev == "" {
			return fmt.Errorf("%w: node %d missing signed_by_prev", ErrLineageMalformed, i)
		}
	}
	return nil
}
