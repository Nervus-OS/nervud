// 见 doc.go 的包说明
//
// 本文件是签名验证的密码学核心（应用层架构决策 §2）：Ed25519 多角色并列验签、
// 密钥血统（lineage）链式核对，以及三层信任根（内嵌平台根 → trust bundle →
// 各 Package 签名）的加载与裁决。
//
// 边界纪律：
//   - 验签一律【针对字节】——覆盖的是 signDomain || manifest.json 原始字节，
//     绝不把解析后的 Manifest 重新序列化回去比对（sigblock.go 已重申这条）。
//   - 信任根不放在可被文件写权限改动的数据里：平台根编译进二进制，bundle 由它
//     签名，验不过即 fail-closed（应用层架构决策 §2.1）。
package pkgregistry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nervus-os/nervud/internal/identity"
)

var (
	// ErrSignatureInvalid 一条签名的密码学验签失败——这是“已执行验证但不通过”，
	// 与“无法验证”不同：前者是真正的攻击线索/损坏，必须 fail-closed 且记违规
	ErrSignatureInvalid = errors.New("pkgregistry: signature verification failed")

	// ErrKeyIDMismatch 内嵌公钥与其自报的 key_id 不一致（key_id 必须等于公钥的 sha256）
	ErrKeyIDMismatch = errors.New("pkgregistry: key_id does not match embedded public key")

	// ErrUntrustedSigner 某条非 developer 签名的 key_id 不在 trust bundle 中，
	// 或该 key 未被授权担任其自报的角色
	ErrUntrustedSigner = errors.New("pkgregistry: signer key not trusted for its role")

	// ErrLineageBroken lineage 链某一跳的 signed_by_prev 验不过，或节点 key 与其 key_id 不符
	ErrLineageBroken = errors.New("pkgregistry: lineage chain verification failed")

	// ErrDeveloperKeyNotCurrent developer 签名不是由 lineage 最后一个节点（当前有效密钥）产生
	ErrDeveloperKeyNotCurrent = errors.New("pkgregistry: developer signature not from current lineage key")

	// ErrNoDeveloperSignature 动态安装包缺少 developer 角色签名——它是身份与
	// 血统的锚点，没有它就无法做 TOFU/防身份劫持
	ErrNoDeveloperSignature = errors.New("pkgregistry: package has no developer signature")

	// ErrTrustBundleInvalid trust bundle 自身的平台根签名验不过
	ErrTrustBundleInvalid = errors.New("pkgregistry: trust bundle signature invalid")
)

// keyIDOf 计算一个公钥的 canonical key_id："sha256:" + hex(sha256(rawpubkey))
func keyIDOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// developerSignMessage 返回 developer 签名【应当覆盖】的字节
//
// 无 lineage（单节点 TOFU）：只覆盖 manifestSigDomain || manifestBytes，向下兼容。
// 有 lineage：额外把整条血统摘要绑进来——否则 developer 只签 manifest，血统字段
// 就是可替换的，中间人能给一份真实 B 签名的包换上任意 A_evil→B 血统、毒化 root
// （P1-5，应用层架构决策 §2.4/§2.6）。绑定用血统全部节点 key_id 的有序摘要：
// 每个 key_id 后接 NUL 分隔（key_id 是 "sha256:hex"，不含 NUL，无歧义）
func developerSignMessage(manifestBytes []byte, l *Lineage) []byte {
	msg := append(append([]byte{}, manifestSigDomain...), manifestBytes...)
	if l == nil {
		return msg
	}
	h := sha256.New()
	for _, n := range l.Nodes {
		h.Write([]byte(n.KeyID))
		h.Write([]byte{0})
	}
	msg = append(msg, lineageBindDomain...)
	msg = append(msg, h.Sum(nil)...)
	return msg
}

// decodePubKey 解 base64 并核对长度必须是 ed25519 公钥长度
func decodePubKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("pkgregistry: decode pubkey: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pkgregistry: pubkey has wrong length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// DevIdentity 是 developer 角色的身份与血统摘要，供升级期 TOFU/防身份劫持记账
// （应用层架构决策 §2.4/§2.6）。无 lineage 时 = 单节点，Root==Current，Len==1
type DevIdentity struct {
	RootKeyID    string
	CurrentKeyID string
	LineageLen   int
	KeyIDs       []string // 血统全部节点 key_id，按序；升级时"前 lineage_len 个逐一相等"要用
}

// SignerSet 是一次多角色验签的结论
type SignerSet struct {
	// Trust 是这些签名【单独】能证明的最高信任。注意 Arbitrate 还会与安装来源
	// 求交：动态安装即便带 platform 签名也只能是 Ordinary（应用层架构决策 §2.2 红线 1）
	Trust        identity.TrustProfile
	HasDeveloper bool
	// HasOEM 表示存在一条【授予 OEM 信任】的签名（oem-service / oem-app）。
	// 注意 oem-trust-software 不计入这里——它只是副署，仍是 Ordinary（见 HasOEMCountersign）
	HasOEM bool
	// HasPlatform 表示存在一条授予 Platform 信任的签名（platform-release / platform-systemapp）
	HasPlatform bool
	// HasOEMCountersign 表示存在任意一条 OEM 角色签名（oem-service / oem-app /
	// oem-trust-software）——满足设备策略 require_oem_countersign 的准入门槛。
	// 与 HasOEM 分开：oem-trust-software 是“OEM 认可第三方包可装”的副署，满足副署
	// 要求但【不提升 trust】（应用层架构决策 §2.5）
	HasOEMCountersign bool
	// Roles 是本次验签里出现的全部签名角色（去重前，按签名顺序）。供权限裁决的
	// RequireSignerRole 用（应用层架构决策 §2.2）——某些最危险权限只给特定角色签的包
	Roles []SignerRole
	// Dev 仅当存在 developer 角色签名时非 nil
	Dev *DevIdentity
}

// RoleStrings 返回 Roles 的字符串形式，供 permission.Intersect 的 RequireSignerRole
// 裁决（permission 不 import pkgregistry.SignerRole，只认字符串）
func (s SignerSet) RoleStrings() []string {
	out := make([]string, 0, len(s.Roles))
	for _, r := range s.Roles {
		out = append(out, string(r))
	}
	return out
}

// Policy 是设备级签名策略，来自 trust bundle（应用层架构决策 §2.5）
type Policy struct {
	RequireOEMCountersign bool `json:"require_oem_countersign"`
}

// trustedKey 是 trust bundle 里一把被授权的非 developer 签名密钥
type trustedKey struct {
	pub   ed25519.PublicKey
	roles map[SignerRole]struct{}
}

// TrustStore 是三层信任根的运行期视图（应用层架构决策 §2.1/§2.2）
//
// 零值不可用；由 LoadTrustStore 或（测试用）newTrustStore 构造
type TrustStore struct {
	// byKeyID 是 bundle 里全部被授权签名密钥（平台中间密钥 + OEM 密钥），
	// 各自带被授权担任的角色集合。developer 角色不在此表——它自签，公钥内嵌在
	// manifest.sig 里，key_id 即公钥 sha256
	byKeyID map[string]trustedKey
	policy  Policy
}

func (ts TrustStore) policyRequireOEMCountersign() bool { return ts.policy.RequireOEMCountersign }

// ---- trust bundle wire 格式（应用层架构决策 §2.1）------------------------

const trustBundleFormatV1 = 1

// bundleKey 是 bundle 里一条被授权密钥。roles 声明它能担任哪些角色——一把
// platform-release 密钥不能拿来冒充 oem-service，反之亦然（最小授权）
type bundleKey struct {
	KeyID string       `json:"key_id"`
	Key   string       `json:"key"`
	Roles []SignerRole `json:"roles"`
}

// trustBundle 是 /usr/share/nervus/trust/trust-bundle.json 的内容
//
// v1 简化（相对方案 §2.2 的两层 OEM 委托）：把“OEM 根签 OEM 子密钥”这一层
// 折叠掉，bundle 直接列出全部被授权的叶子签名密钥（平台的与 OEM 的）各带角色。
// 安全属性不变——授权谁能签仍然只由“平台根签过的 bundle”决定，而不是文件写权限。
// 两层委托留待 v2 真有密钥管理需求时再加
type trustBundle struct {
	Format       int         `json:"format"`
	PlatformKeys []bundleKey `json:"platform_keys"`
	OEMKeys      []bundleKey `json:"oem_keys"`
	Policy       Policy      `json:"policy"`
}

// embeddedPlatformRootB64 是编译进二进制的平台根公钥（应用层架构决策 §2.1）。
//
// 生产构建通过 -ldflags "-X ...embeddedPlatformRootB64=<base64>" 注入，或直接改这里
// 重新编译。空值 = 未注入（开发构建）：LoadTrustStore 会 fail-closed（拒绝装载
// 任何 bundle），于是 scanSystemImage 拿不到非 Ordinary 信任——这正是“验不过就
// fail-closed，绝不假装验证通过”的体现，而不是一个可被利用的松动开关
// 必须是包级 var（不能是 const）：生产构建用 -ldflags "-X ...=<base64>" 注入，
// 而 -X 只能改 var。gochecknoglobals 对此误报——这是 ldflags 注入点的既定形态
//
//nolint:gochecknoglobals // ldflags -X injection target; cannot be const
var embeddedPlatformRootB64 = ""

// DefaultTrustDir 是只读镜像内的信任材料目录（应用层架构决策 §2.1）
const DefaultTrustDir = "/usr/share/nervus/trust"

// LoadTrustStore 用【内嵌】平台根验证 dir 下的 trust bundle，构造 TrustStore
//
// 验不过、缺文件或内嵌根为空 → 返回错误；调用方（main.go）据此 fail-closed：
// 一切非 Ordinary 信任都发不出去，但系统仍能装/跑 Ordinary 包
func LoadTrustStore(dir string) (TrustStore, error) {
	if embeddedPlatformRootB64 == "" {
		return TrustStore{}, fmt.Errorf("%w: no embedded platform root (dev build)", ErrTrustBundleInvalid)
	}
	root, err := decodePubKey(embeddedPlatformRootB64)
	if err != nil {
		return TrustStore{}, fmt.Errorf("pkgregistry: embedded platform root: %w", err)
	}
	bundleBytes, err := os.ReadFile(filepath.Join(dir, "trust-bundle.json"))
	if err != nil {
		return TrustStore{}, fmt.Errorf("pkgregistry: read trust bundle: %w", err)
	}
	sigBytes, err := os.ReadFile(filepath.Join(dir, "trust-bundle.sig"))
	if err != nil {
		return TrustStore{}, fmt.Errorf("pkgregistry: read trust bundle sig: %w", err)
	}
	return parseTrustBundle(root, bundleBytes, sigBytes)
}

// trustBundleSigDomain 覆盖 trust bundle 原始字节的签名域前缀。const string 同
// sigblock.go 的三个域前缀：真常量、不可运行期改写、避开 gochecknoglobals
const trustBundleSigDomain = "nervus-trust-bundle-v1\x00"

// parseTrustBundle 用 root 验签 bundle 原始字节，再解析成 TrustStore
//
// 拆成独立函数（不直接读文件）是为了让测试能用自造的密钥对走完整条验签路径，
// 无需在测试里摆一个真实的内嵌根
func parseTrustBundle(root ed25519.PublicKey, bundleBytes, sigB64 []byte) (TrustStore, error) {
	sig, err := base64.StdEncoding.DecodeString(string(sigB64))
	if err != nil {
		return TrustStore{}, fmt.Errorf("pkgregistry: decode bundle sig: %w", err)
	}
	msg := append(append([]byte{}, trustBundleSigDomain...), bundleBytes...)
	if !ed25519.Verify(root, msg, sig) {
		return TrustStore{}, ErrTrustBundleInvalid
	}

	var tb trustBundle
	if err := json.Unmarshal(bundleBytes, &tb); err != nil {
		return TrustStore{}, fmt.Errorf("pkgregistry: decode trust bundle: %w", err)
	}
	if tb.Format != trustBundleFormatV1 {
		return TrustStore{}, fmt.Errorf("%w: format %d", ErrTrustBundleInvalid, tb.Format)
	}

	byID := make(map[string]trustedKey)
	add := func(bk bundleKey, allowed map[SignerRole]struct{}) error {
		pub, err := decodePubKey(bk.Key)
		if err != nil {
			return err
		}
		if keyIDOf(pub) != bk.KeyID {
			return fmt.Errorf("%w: bundle key %q", ErrKeyIDMismatch, bk.KeyID)
		}
		roles := make(map[SignerRole]struct{}, len(bk.Roles))
		for _, r := range bk.Roles {
			if _, ok := allowed[r]; !ok {
				return fmt.Errorf("%w: key %q claims disallowed role %q", ErrUntrustedSigner, bk.KeyID, r)
			}
			roles[r] = struct{}{}
		}
		byID[bk.KeyID] = trustedKey{pub: pub, roles: roles}
		return nil
	}
	platformRoles := map[SignerRole]struct{}{RolePlatformRelease: {}, RolePlatformSystemApp: {}}
	oemRoles := map[SignerRole]struct{}{RoleOEMService: {}, RoleOEMApp: {}, RoleOEMTrustSoftware: {}}
	for _, bk := range tb.PlatformKeys {
		if err := add(bk, platformRoles); err != nil {
			return TrustStore{}, err
		}
	}
	for _, bk := range tb.OEMKeys {
		if err := add(bk, oemRoles); err != nil {
			return TrustStore{}, err
		}
	}
	return TrustStore{byKeyID: byID, policy: tb.Policy}, nil
}

// VerifySignature 校验 manifestBytes 与其分离签名 sigBlock，返回多角色结论
//
// manifestBytes 必须是签名所覆盖的原始字节。任一条签名验签失败即整体错误
// （ErrSignatureInvalid 等）——这是“已验证但不通过”，与“无法验证”不同，
// 调用方据此记违规而非能力缺口
func (ts TrustStore) VerifySignature(manifestBytes, sigBlock []byte) (SignerSet, error) {
	sb, err := ParseSignatureBlock(sigBlock)
	if err != nil {
		return SignerSet{}, err
	}

	// 先把 lineage 链核对通过，拿到“当前有效 developer 密钥”
	var currentDevKeyID string
	var dev *DevIdentity
	if sb.Lineage != nil {
		id, derr := verifyLineage(sb.Lineage)
		if derr != nil {
			return SignerSet{}, derr
		}
		dev = id
		currentDevKeyID = id.CurrentKeyID
	}

	msg := append(append([]byte{}, manifestSigDomain...), manifestBytes...)
	// developer 签名覆盖的字节额外绑定血统（见 developerSignMessage），其余角色
	// 只覆盖 manifest 原始字节
	devMsg := developerSignMessage(manifestBytes, sb.Lineage)
	set := SignerSet{Trust: identity.TrustOrdinary}

	for _, s := range sb.Signatures {
		sig, derr := base64.StdEncoding.DecodeString(s.Sig)
		if derr != nil {
			return SignerSet{}, fmt.Errorf("pkgregistry: decode sig for %q: %w", s.KeyID, derr)
		}

		var pub ed25519.PublicKey
		verifyMsg := msg
		switch s.Role {
		case RoleDeveloper:
			pub, derr = decodePubKey(s.Key)
			if derr != nil {
				return SignerSet{}, derr
			}
			if keyIDOf(pub) != s.KeyID {
				return SignerSet{}, fmt.Errorf("%w: developer %q", ErrKeyIDMismatch, s.KeyID)
			}
			// 有 lineage 时，developer 签名必须由血统最后一个节点产生
			if sb.Lineage != nil && s.KeyID != currentDevKeyID {
				return SignerSet{}, fmt.Errorf("%w: sig key %q, current %q",
					ErrDeveloperKeyNotCurrent, s.KeyID, currentDevKeyID)
			}
			verifyMsg = devMsg // developer 覆盖“manifest + 血统绑定”
		default:
			tk, ok := ts.byKeyID[s.KeyID]
			if !ok {
				return SignerSet{}, fmt.Errorf("%w: %q", ErrUntrustedSigner, s.KeyID)
			}
			if _, ok := tk.roles[s.Role]; !ok {
				return SignerSet{}, fmt.Errorf("%w: %q not authorized for %q", ErrUntrustedSigner, s.KeyID, s.Role)
			}
			// 内嵌公钥（可选）必须与信任库里 key_id 对应的公钥逐字节一致
			if s.Key != "" {
				embedded, eerr := decodePubKey(s.Key)
				if eerr != nil {
					return SignerSet{}, eerr
				}
				if !embedded.Equal(tk.pub) {
					return SignerSet{}, fmt.Errorf("%w: embedded key for %q differs from bundle", ErrKeyIDMismatch, s.KeyID)
				}
			}
			pub = tk.pub
		}

		if !ed25519.Verify(pub, verifyMsg, sig) {
			return SignerSet{}, fmt.Errorf("%w: %s by %q", ErrSignatureInvalid, s.Role, s.KeyID)
		}

		set.Roles = append(set.Roles, s.Role)
		switch s.Role {
		case RoleDeveloper:
			set.HasDeveloper = true
			if dev == nil {
				// 无 lineage：单节点身份，root==current==该 key
				dev = &DevIdentity{RootKeyID: s.KeyID, CurrentKeyID: s.KeyID, LineageLen: 1, KeyIDs: []string{s.KeyID}}
			}
		case RolePlatformRelease, RolePlatformSystemApp:
			set.HasPlatform = true
		case RoleOEMService, RoleOEMApp:
			// 授予 OEM 信任的角色
			set.HasOEM = true
			set.HasOEMCountersign = true
		case RoleOEMTrustSoftware:
			// 仅副署（OEM 认可第三方包可装）：满足副署门槛，但【不提升 trust】
			// （应用层架构决策 §2.5）——故意不置 HasOEM
			set.HasOEMCountersign = true
		}
	}

	// 有 lineage 却没有一条 developer 签名 = 血统无锚点，拒绝
	if sb.Lineage != nil && !set.HasDeveloper {
		return SignerSet{}, ErrNoDeveloperSignature
	}
	set.Dev = dev

	switch {
	case set.HasPlatform:
		set.Trust = identity.TrustPlatform
	case set.HasOEM:
		set.Trust = identity.TrustOEM
	default:
		set.Trust = identity.TrustOrdinary
	}
	return set, nil
}

// verifyLineage 逐跳核对血统链，返回身份摘要（应用层架构决策 §2.4）
//
// 每个节点的 key 必须与其 key_id 相符；非首节点的 signed_by_prev 必须是上一个
// 节点对 (lineageSigDomain || key_id || key) 的有效签名——即“上一把密钥授权了
// 下一把接替”。返回的 CurrentKeyID 是最后一个节点
func verifyLineage(l *Lineage) (*DevIdentity, error) {
	keyIDs := make([]string, len(l.Nodes))
	var prevPub ed25519.PublicKey
	for i, n := range l.Nodes {
		pub, err := decodePubKey(n.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: node %d: %v", ErrLineageBroken, i, err)
		}
		if keyIDOf(pub) != n.KeyID {
			return nil, fmt.Errorf("%w: node %d key_id mismatch", ErrLineageBroken, i)
		}
		if i > 0 {
			sig, err := base64.StdEncoding.DecodeString(n.SignedByPrev)
			if err != nil {
				return nil, fmt.Errorf("%w: node %d signed_by_prev decode: %v", ErrLineageBroken, i, err)
			}
			// 消息 = 域前缀 || 本节点 key_id || 本节点原始公钥字节
			msg := append(append(append([]byte{}, lineageSigDomain...), []byte(n.KeyID)...), pub...)
			if !ed25519.Verify(prevPub, msg, sig) {
				return nil, fmt.Errorf("%w: node %d signed_by_prev invalid", ErrLineageBroken, i)
			}
		}
		keyIDs[i] = n.KeyID
		prevPub = pub
	}
	return &DevIdentity{
		RootKeyID:    keyIDs[0],
		CurrentKeyID: keyIDs[len(keyIDs)-1],
		LineageLen:   len(keyIDs),
		KeyIDs:       keyIDs,
	}, nil
}
