// 本文件是"装之前先看看"的只读路径: 解析并验签一个 staging 里的包, 算出它申请
// 的 USER_CONSENT 权限清单, 不写任何状态.
//
// # 为什么必须有这条路
//
// USER_CONSENT 权限的运行期状态默认是 NOT_REQUESTED, 而应用没有"请求权限"的
// API. 于是唯一能让它变成 GRANTED 的时机是安装期: 确认屏把该包申请的敏感权限
// 摊给用户, 用户点头的那批随 InstallRequest 一起带进来 (见 applyInstallConsent).
//
// 但确认屏此前【无从知道那批权限是什么】: ListGrants 与 List 都只覆盖已装包,
// 而待装的包还不在 Catalog 里. 它手上只有一个 .nspkg 路径.
//
// # 为什么解析留在内核
//
// 另一条路是让确认屏自己解包读 manifest. 那等于把【签名验证之前的不受信内容
// 解析】放进一个持有 perm.permission.admin 的进程里 —— 全系统权限最高的那个
// 界面, 攻击面上最不该放解析器的地方.
//
// 更根本的是分工: 确认屏不做任何安全判定, 它连"这条权限是不是 USER_CONSENT"
// 都不该自己判断. 那需要 Catalog 里的权限定义, 而定义只有内核有.
package pkgregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/catalog"
)

// ErrPermissionDefinitionUnknown 包申请了一条 Catalog 里没有定义的权限.
//
// Inspect 不因此失败: 一条不认识的权限在安装裁决时会被 IntersectAt 拒掉,
// 那才是权威结论. 这里只是不把它列进确认屏 —— 显示一条没有文案的权限,
// 用户无从判断该不该同意.
var ErrPermissionDefinitionUnknown = errors.New("pkgregistry: permission is not defined in the catalog")

// ConsentPermission 是确认屏要展示的一条待同意权限.
//
// 文案由 Catalog 的权限定义给出而不是界面写死: 第三方包可以定义自己的权限,
// 界面不可能预先知道它们的名称与说明.
type ConsentPermission struct {
	ID              string
	DisplayNameZhCN string
	DisplayNameEN   string
	DescriptionZhCN string
	DescriptionEN   string
	RiskClass       ipcv1.RiskClass
}

// InspectResult 是一次只读检视的结果.
type InspectResult struct {
	// 包自称的身份. 来自 manifest, 【已通过验签】但尚未经过安装裁决 ——
	// Inspect 成功不代表 Install 会成功 (ABI 不匹配, 版本降级, OEM 副署缺失
	// 等都要等到真正安装时才裁决).
	PackageID   string
	Version     string
	VersionCode uint64

	// ConsentPermissions 是本包申请的, 需要用户点头的敏感权限.
	//
	// 已过滤成 GrantMode == USER_CONSENT 这一档: 其它模式没有"要不要同意"
	// 这回事 —— NORMAL 装上即生效, PRIVILEGED / SYSTEM_ONLY 由来源与签名决定.
	// 把它们混进来只会让确认屏显示一堆用户无从选择的条目.
	//
	// 按权限 ID 排序, 让确认屏的条目顺序稳定 (同一个包每次看到的顺序一样).
	ConsentPermissions []ConsentPermission

	// ManifestDigest 是 sha256(manifest 原始字节) 的十六进制串, 用来把这次
	// Inspect 的结果与随后那次 Install 绑在同一份内容上.
	//
	// # 它关的是哪个缝
	//
	// .nspkg 放在跨包共享的 user-data 里 (见 pkgmanagerd 的 handoffRoot),
	// 因此调用方在 Inspect 与 Install 【之间】完全可以把文件换掉: 用户在确认屏
	// 上看到的权限清单来自 A, 真正装进去的是 B. 两次调用各自都是合法的, 没有
	// 任何一步能单独发现这件事 —— 只有把两次绑起来才能.
	//
	// 用法: 确认屏把本字段原样回传给 Install, 内核比对不符即拒。
	//
	// # 为什么 manifest 的摘要就够, 不用遍历整棵树
	//
	// manifest 里含【全部文件的 digests】, 而 manifest 本身被签名覆盖. 因此
	// "manifest 字节相同" 蕴含 "所有文件的期望摘要相同", 而文件内容与那些摘要
	// 是否一致由 Install 的 VerifyDigests 复核. 换掉任何一个文件都要么让
	// VerifyDigests 失败, 要么需要改 manifest —— 而那会改变本摘要.
	//
	// 所以这里不需要再遍历一次文件树: 那是 Install 已经做的事, 在 Inspect 里
	// 重做一遍只为了算个标识, 会让"看一眼要什么权限"多花几秒.
	ManifestDigest string
}

// Inspect 解析并验签 staging 里的包, 返回它申请的 USER_CONSENT 权限清单.
//
// # 它做了什么, 没做什么
//
//	做: 解析 manifest -> 多角色验签 (devmode 放宽与 Install 一致) ->
//	    按 Catalog 的权限定义筛出 USER_CONSENT 那一档
//	不做: 信任裁决之后的任何一步 —— 不查 ABI, 不核 digest, 不做升级裁决,
//	      不分配 UID, 不落盘, 不改 Registry / Catalog / 权限投影
//
// 【验签是必须的】. 一个签名无效的包, 它 manifest 里写的权限清单也就无从当真 ——
// 把它显示给用户等于让攻击者决定确认屏上出现什么文字. 因此这里与 Install 走
// 同一个 VerifySignature, 包括 devmode 的放宽条件 (否则开发机上装自己的包会
// 在确认屏这一步就卡住, 而 Install 本来是放行的).
//
// # 为什么不核 digest
//
// digest 复核要遍历整棵树算 sha256, 而 Inspect 的目的只是读 manifest 里的权限
// 清单 —— 那份 manifest 本身已经被验签覆盖. 真正的 digest 复核在 Install 里,
// 那是决定"要不要把这些文件装进系统"的地方. 在这里再做一遍只是让确认屏多等
// 几秒, 挡不住任何东西: 一个 digest 不符的包会在 Install 时被拒, 而用户此时
// 还没点同意.
//
// # 不持锁
//
// Inspect 不改任何状态, 因此不需要 m.mu. 它读 m.definitions.Current() 拿权限
// 定义 —— 那是一份不可变快照, 并发安装发布新快照不会让本次读到半个状态.
func (m *Module) Inspect(ctx context.Context, stagingDir string) (InspectResult, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(stagingDir, ManifestFileName))
	if err != nil {
		return InspectResult{}, fmt.Errorf("pkgregistry: read %s: %w", ManifestFileName, err)
	}
	sigBlock, err := os.ReadFile(filepath.Join(stagingDir, SignatureFileName))
	if err != nil {
		return InspectResult{}, fmt.Errorf("pkgregistry: read %s: %w", SignatureFileName, err)
	}

	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return InspectResult{}, err
	}

	// ---- 验签. 与 Install 同一条路, 包括 devmode 放宽 ----
	dev := loadDevMode(m.stateDir)
	if _, sigErr := m.trust.VerifySignature(manifestBytes, sigBlock); sigErr != nil {
		m.aud.Record(ctx, audit.Event{
			Action:  "pkgregistry.Inspect.VerifySignature",
			Subject: manifest.PackageID,
			Denied:  true,
			Err:     sigErr,
		})
		if !dev.Enabled || !dev.AllowUnverifiedSignature {
			return InspectResult{}, sigErr
		}
		m.aud.Record(ctx, audit.Event{
			Action:  "pkgregistry.Inspect.devmode",
			Subject: manifest.PackageID,
			Detail:  "relaxed: allow_unverified_signature",
		})
	}

	// ---- 按 Catalog 定义筛出 USER_CONSENT 那一档 ----
	//
	// 用 Current() 而不是像 Install 那样 Prepare 一份候选 Catalog: Inspect 是
	// 只读的, 而 Prepare 要装载本包的 ProviderArtifacts 并校验整个候选目录 ——
	// 那会让"看一眼这个包要什么权限"因为一个与权限无关的目录冲突而失败.
	//
	// 代价是【包自己定义的权限看不到】: 它们要等本包进 Catalog 才有定义, 而那
	// 是 Install 之后的事. 那类权限因此在确认屏上不会出现, 用户也就无从同意,
	// 运行期保持 NOT_REQUESTED —— fail closed, 不会因为看不到而白拿到.
	// 用户之后仍可在权限管理界面里补上.
	snapshot := m.definitions.Current()
	if snapshot == nil {
		return InspectResult{}, ErrCatalogUnavailable
	}

	out := InspectResult{
		PackageID:   manifest.PackageID,
		Version:     manifest.Version,
		VersionCode: manifest.VersionCode,
		// 对【验签覆盖的那份原始字节】算摘要, 而不是对 ParseManifest 之后的
		// 结构体重新序列化: 后者会把 manifest 里我们不认识的字段丢掉, 于是两个
		// 内容不同的包可能算出同一个摘要 —— 那正是本字段要防的事.
		ManifestDigest: hex.EncodeToString(sha256Sum(manifestBytes)),
	}
	for _, permissionID := range manifest.Permissions {
		definition, ok := snapshot.Permission(permissionID)
		if !ok {
			// 不认识的权限不进清单, 也不让整次 Inspect 失败: 权威裁决在
			// Install 的 IntersectAt, 它会拒掉这一条. 记一条审计, 否则
			// "我申请的权限没出现在确认屏上"没有任何痕迹可查
			m.aud.Record(ctx, audit.Event{
				Action:  "pkgregistry.Inspect.permission",
				Subject: manifest.PackageID,
				Denied:  true,
				Err:     ErrPermissionDefinitionUnknown,
				Detail:  permissionID,
			})
			continue
		}
		if definition.GrantMode != ipcv1.GrantMode_GRANT_MODE_USER_CONSENT {
			continue
		}
		out.ConsentPermissions = append(out.ConsentPermissions, consentPermission(definition))
	}
	// 排序让确认屏的条目顺序稳定. manifest.Permissions 的书写顺序是包作者的
	// 自由, 不该决定用户看到的顺序
	sort.Slice(out.ConsentPermissions, func(i, j int) bool {
		return out.ConsentPermissions[i].ID < out.ConsentPermissions[j].ID
	})

	m.aud.Record(ctx, audit.Event{
		Action:  "pkgregistry.Inspect",
		Subject: manifest.PackageID,
		Detail: fmt.Sprintf("version=%s consent_permissions=%d",
			manifest.Version, len(out.ConsentPermissions)),
	})
	return out, nil
}

func consentPermission(d catalog.PermissionDefinition) ConsentPermission {
	return ConsentPermission{
		ID:              d.ID,
		DisplayNameZhCN: d.DisplayNameZhCN,
		DisplayNameEN:   d.DisplayNameEN,
		DescriptionZhCN: d.DescriptionZhCN,
		DescriptionEN:   d.DescriptionEN,
		RiskClass:       d.RiskClass,
	}
}

// sha256Sum 是 sha256.Sum256 的切片形式, 省掉调用点的 [:] 转换.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// ErrManifestDigestMismatch 装的内容与用户确认时看到的不是同一份.
//
// 只在 InstallTransaction.ExpectedManifestDigest 非空时可能出现. 它不是"包坏了"
// —— 签名与 digest 都可能完全有效, 只是这份包不是确认屏摊给用户看的那一份.
var ErrManifestDigestMismatch = errors.New("pkgregistry: manifest digest does not match the confirmed package")
