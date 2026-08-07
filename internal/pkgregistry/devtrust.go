// 本文件只服务开发构建：在没有内嵌平台根的二进制上，让系统镜像包仍能拿到
// 它签名所声称的 trust。
//
// # 为什么需要它
//
// 生产二进制用 -ldflags 注入 embeddedPlatformRootB64，LoadTrustStore 据此验证
// trust bundle。开发构建没有注入，LoadTrustStore 直接失败，于是 scanSystemImage
// 把每个系统包 fail-closed 到 Ordinary。而 perm.service.register 的门槛是
// MinimumTrust=OEM + GRANT_MODE_PRIVILEGED——结果是【开发机上任何导出公共接口
// 的系统服务都注册不了】，连 pkgmanagerd 的兼容桥也因为要求 TrustPlatform 而
// 不成立。
//
// # 它放松了什么、没放松什么
//
// 【只放松一件事】：这把签名密钥是否由内嵌平台根授权。
//
// 签名本身仍然逐条做真实的 Ed25519 验签，key_id 仍然必须等于公钥的 sha256，
// 角色仍然必须是已知角色，digest 仍然是硬校验。也就是说：
//
//   - 改了二进制 -> digest 不符，照样拒
//   - 改了 manifest -> 验签不过，照样拒
//   - 没有私钥就想冒充某个 key_id -> 签不出来，照样拒
//
// 因此 key_id 是【真实的】，GRANT_MODE_SIGNATURE 的同签名者比对在开发期与生产期
// 语义一致。这一点是刻意的：如果这里编造一个常量 key_id，所有开发包会变成
// 「同一个签名者」，而那种差异只会在某个依赖 SameIdentity 的功能上线后才暴露。
//
// 公钥从哪来：sysmanifest 对非 developer 角色也内嵌公钥（signManifest 的
// Key 字段），注释写明「带上它让开发期（无信任库）也能自查」。本文件正是那句话
// 的兑现。
package pkgregistry

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// LoadDevTrustStore 用系统镜像包自带的内嵌公钥构造一个开发用 TrustStore。
//
// 只扫描 systemPackagesDir 下的 manifest.sig。动态安装包不参与构造，也不需要：
// Arbitrate(SourceDynamicInstall, ...) 无论签名如何都只发 Ordinary，
// 所以这个 store 不会给动态安装路径带来任何额外权力。
//
// 返回的 store 的 policy 取零值（RequireOEMCountersign=false）。开发期不模拟
// 设备级副署策略——那属于 trust bundle 的内容，而这里根本没有 bundle。
func LoadDevTrustStore(systemPackagesDir string, log *slog.Logger) (TrustStore, error) {
	matches, err := filepath.Glob(filepath.Join(systemPackagesDir, "*", SignatureFileName))
	if err != nil {
		return TrustStore{}, fmt.Errorf("pkgregistry: scan dev signatures: %w", err)
	}

	byKeyID := make(map[string]trustedKey)
	for _, sigPath := range matches {
		sigBytes, rerr := os.ReadFile(sigPath)
		if rerr != nil {
			continue
		}
		sb, perr := ParseSignatureBlock(sigBytes)
		if perr != nil {
			// 坏签名块在这里只是「锚不出密钥」。真正的拒绝发生在
			// scanSystemImage 的验签处，错误信息也在那里更贴近原因
			continue
		}
		for _, s := range sb.Signatures {
			// developer 角色自锚定：公钥内嵌在签名块里、验签方本就不查信任库。
			// 把它放进 store 是多余的，也会模糊「谁需要被授权」这条线
			if s.Role == RoleDeveloper || s.Key == "" {
				continue
			}
			pub, derr := decodePubKey(s.Key)
			if derr != nil {
				continue
			}
			// key_id 必须真的是这把公钥的 sha256。不核对的话，一个包可以用
			// 自己的密钥去占用另一个 key_id 的授权位
			if keyIDOf(pub) != s.KeyID {
				continue
			}
			tk, ok := byKeyID[s.KeyID]
			if !ok {
				tk = trustedKey{pub: pub, roles: make(map[SignerRole]struct{})}
			}
			tk.roles[s.Role] = struct{}{}
			byKeyID[s.KeyID] = tk
		}
	}

	if len(byKeyID) == 0 {
		return TrustStore{}, fmt.Errorf(
			"%w: no embedded signer keys found under %s", ErrTrustBundleInvalid, systemPackagesDir)
	}
	if log != nil {
		for keyID, tk := range byKeyID {
			roles := make([]string, 0, len(tk.roles))
			for role := range tk.roles {
				roles = append(roles, string(role))
			}
			log.Warn("pkgregistry: DEV trust anchor accepted without platform root",
				"key_id", keyID, "roles", roles)
		}
	}
	return TrustStore{byKeyID: byKeyID}, nil
}
