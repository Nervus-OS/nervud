// 本文件是最终安装裁决与事务提交的编排: 把 manifest/digest/signature/arbitrate/
// upgrade 这几块独立的复核逻辑, 接到 authority.Gate 的两个特权操作上, 产出一条
// 登记进 Registry 的 Entry
package pkgregistry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

// ErrStagingMetadataMismatch staging 里的 manifest.json/manifest.sig 与调用方提交,
// 已验签的字节不一致 - 验签 A, 落盘 B的信号, 拒绝安装
var ErrStagingMetadataMismatch = errors.New("pkgregistry: staging manifest/signature differs from verified bytes")

// ErrReloadPending means the package/catalog commit succeeded, but the running
// instance could not yet be switched to the new package generation. The new
// registry state is authoritative and the caller must retry the lifecycle
// reload; reporting success here would leave a committed but unavailable
// provider indistinguishable from a healthy upgrade.
var ErrReloadPending = errors.New("pkgregistry: package committed, runtime reload pending")

// verifyStagingMetadata 核对 staging 目录里的 manifest.json 与 manifest.sig 与调用方
// 传入, 已经过验签的字节逐字节一致. 这样落盘 (提交) 的那棵树里的 manifest/sig
// 就是被验证的同一个对象, 堵住 digest 豁免这两个文件所留下的验签与落盘不是同一份
// 缺口. payload 文件由 VerifyDigests 覆盖, 此处只补上被豁免的两份元数据
func verifyStagingMetadata(stagingDir string, manifestBytes, sigBlock []byte) error {
	mGot, err := os.ReadFile(filepath.Join(stagingDir, ManifestFileName))
	if err != nil {
		return fmt.Errorf("%w: read staging manifest: %v", ErrStagingMetadataMismatch, err)
	}
	if !bytes.Equal(mGot, manifestBytes) {
		return fmt.Errorf("%w: manifest.json", ErrStagingMetadataMismatch)
	}
	sGot, err := os.ReadFile(filepath.Join(stagingDir, SignatureFileName))
	if err != nil {
		return fmt.Errorf("%w: read staging signature: %v", ErrStagingMetadataMismatch, err)
	}
	if !bytes.Equal(sGot, sigBlock) {
		return fmt.Errorf("%w: manifest.sig", ErrStagingMetadataMismatch)
	}
	return nil
}

// PackageInstaller 是 pkgregistry 对 authority.Gate 的窄接口依赖
//
// main.go 的装配范式: 消费者包定义自己需要的最小接口, *authority.Gate 隐式满足
type PackageInstaller interface {
	InstallVerifiedPackage(ctx context.Context, subj authority.Subject, req authority.InstallVerifiedPackageRequest) error
	CreatePrivateDataDirectory(ctx context.Context, subj authority.Subject, req authority.CreateDataDirRequest) (authority.DirHandle, error)
	// RemovePackageTree 递归删除已安装 Package 的代码或数据目录 (卸载 / 安装失败补偿)
	RemovePackageTree(ctx context.Context, subj authority.Subject, req authority.RemovePackageTreeRequest) error
	// EnsureAppUser 把已分配的 App UID 登记进系统用户库. 幂等.
	//
	// systemd 的 User= 即便给数字 UID 也要求它能被 NSS 解析, 否则 spawn 在
	// step USER 失败 (217/USER). 没有这一步, 任何 Package 组件都起不来.
	EnsureAppUser(ctx context.Context, subj authority.Subject, req authority.EnsureAppUserRequest) error
	// SetUserDataAccess 增删用户文档区 ACL 里某个 UID 的条目.
	//
	// 卸载路径需要它: ClearPackage 只清 _grants.json 里的运行期状态, 而访问
	// 权限现在落在文件系统的 ACL 上. 不摘掉那条, UID 被下一个包复用时它就
	// 白拿到了用户文档区的写权限, 且没有任何界面显示过这次授予
	SetUserDataAccess(ctx context.Context, subj authority.Subject, req authority.SetUserDataAccessRequest) error
}

// IdentityUpdater 是 pkgregistry 对 identity.Registry 的窄接口依赖:
// 只需要全量替换那份瘦投影, 不需要 Lookup/Resolve 等读侧方法
type IdentityUpdater interface {
	Replace(pkgs []identity.Package) error
}

// PermissionArbiter 是 pkgregistry 对 permission.Registry 的窄接口依赖:
// Intersect 做安装时的权限裁决, Replace 把 GrantedPermissions 全量投影推送出去.
// 运行时两个方法都由同一个 *permission.Registry 实例满足
type PermissionArbiter interface {
	IntersectAt(
		definitions *catalog.Snapshot,
		requested []string,
		source catalog.SourceKind,
		trust identity.TrustProfile,
		signers catalog.SignerEvidence,
	) (granted, denied []string)
	Replace(grants []permission.Grant) error
	// ClearPackage 删除某 Package 的运行期授予状态 (卸载用)
	ClearPackage(packageID string) error
	// SetRuntimeState 设置一条 USER_CONSENT 权限的运行期授予状态.
	//
	// 安装期默认授予用它落库: 装完之后那批权限直接变成 Granted.
	// 它自带两道前置校验 (必须是 USER_CONSENT, 且必须已在安装期授予集合里)
	SetRuntimeState(packageID, permissionID string, state permission.GrantState) error
	// GrantStateOf 读一条权限当前的运行期授予状态.
	//
	// 升级路径必须有它: 卸载才清 _grants.json (见 lifecycle.go 的 ClearPackage
	// 调用点), 升级不清. 因此重装时旧决定还在, 而"用户上次关掉的权限"绝不能
	// 因为一次版本更新被悄悄打开 - 那等于给了每个应用一条绕过用户决定的路.
	GrantStateOf(packageID, permissionID string) permission.GrantState
}

// InstallTransaction 是一次装包事务的输入
type InstallTransaction struct {
	ManifestBytes []byte // 未解析的原始 manifest.json 字节; 签名针对这份原始字节验证
	SigBlock      []byte // 分离签名 manifest.sig
	StagingDir    string // pkgmanagerd 产出的, 已展开的 staging 目录
	Source        Source

	// ConsentedPermissions 是用户在安装确认屏上点头的那批权限.
	//
	// 由确认 UI 采集后原样带进来. 内核【不信任这份清单本身】, 只把它当成一个
	// 上限: 真正落库的是它与安装期授予集合, 以及 USER_CONSENT 这一档的交集
	//  (见 applyInstallConsent). 一份夸大的清单不会让任何包多拿到一条权限
	//
	// 为空即"没有任何权限被同意", 装包照常进行 - 那些权限运行期就是拒绝状态,
	// 用户之后仍可以在设置里补上
	ConsentedPermissions []string
}

// Install 执行 动态安装流程里nervud 独立复核... 直到 Registry 登记的
// 那一段. 步骤: 解析 manifest -> 多角色验签 (+devmode 放宽) -> 信任裁决 -> OEM 副署
// 准入 -> Host ABI 匹配 -> digest 复核 -> 升级裁决 (防降级+防身份劫持) -> 权限裁决 ->
// 分配稳定 UID -> Authority 原子提交 -> 登记
//
// 任一步失败即整体返回错误, 不留半成品
func (m *Module) Install(ctx context.Context, tx InstallTransaction) (Entry, error) {
	// 串行化全部状态变更. 装包不是高频路径, 一把大锁挡住并发安装争抢 UID
	// 分配器与 List -> Replace 丢更新
	m.mu.Lock()
	defer m.mu.Unlock()
	previousEntries := m.registry.List()

	// Install 是动态安装专用入口, 只接受 SourceDynamicInstall (修复).
	// 系统镜像包绝不走这里 - 它们由 scanSystemImage 直接构造 Entry. 若允许调用方
	// 传 SourceSystemImage, 就能绕过 developer 必签 / OEM 副署等只在动态分支执行的准入,
	// 还能经 Arbitrate 白拿系统 trust. 两条入口不可混用
	if tx.Source != SourceDynamicInstall {
		err := fmt.Errorf("%w: Install only accepts dynamic-install source, got %q", ErrInvalidSource, tx.Source)
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	manifest, err := ParseManifest(tx.ManifestBytes)
	if err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	// 修复: 验证的 manifest/签名必须与落盘树里的逐字节一致. digest.go 有意
	// 豁免 manifest.json/manifest.sig 的 Extra 检查 (它们不能自散列), 因此若不在此
	// 显式比对, 攻击者可验签 A, 落盘 B - tx.ManifestBytes 过了验签, staging 里却
	// 放另一份 manifest.json, 提交后重启扫描读到的是未验证的那份
	if err := verifyStagingMetadata(tx.StagingDir, tx.ManifestBytes, tx.SigBlock); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	// 修复: 动态安装不得占用系统镜像包的 package_id. 否则可覆盖系统 Entry,
	// 继承其身份, 并在重启扫描时制造重复 ID
	if cur, ok := m.registry.Lookup(manifest.PackageID); ok && cur.Source == SourceSystemImage {
		err := fmt.Errorf("%w: %q is a system-image package", ErrSystemPackageImmutable, manifest.PackageID)
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	dev := loadDevMode(m.stateDir)

	// ---- 多角色验签 ----
	signers, sigErr := m.trust.VerifySignature(tx.ManifestBytes, tx.SigBlock)
	if sigErr != nil {
		// 记审计区分已验证但失败 (攻击/损坏) 与无法验证, 但两者裁决一致:
		// 默认拒绝, 仅 devmode 显式放宽时才允许
		m.aud.Record(ctx, audit.Event{
			Action: "pkgregistry.VerifySignature", Subject: manifest.PackageID, Denied: true, Err: sigErr,
		})
		if !dev.Enabled || !dev.AllowUnverifiedSignature {
			m.auditInstall(ctx, tx, false, sigErr)
			return Entry{}, sigErr
		}
		// devmode 放宽: 允许装未验证签名的包, 但身份视为无锚点, trust 仍 Ordinary
		m.aud.Record(ctx, audit.Event{
			Action: "pkgregistry.Install.devmode", Subject: manifest.PackageID,
			Detail: "relaxed: allow_unverified_signature",
		})
		signers = SignerSet{Trust: identity.TrustOrdinary}
	} else if tx.Source == SourceDynamicInstall && !signers.HasDeveloper {
		// 验签通过但没有 developer 角色签名: 动态安装缺少身份锚点, 拒绝
		m.auditInstall(ctx, tx, false, ErrNoDeveloperSignature)
		return Entry{}, ErrNoDeveloperSignature
	}

	trust := Arbitrate(tx.Source, signers)

	// ---- OEM 副署准入----
	// 用 HasOEMCountersign 而非 HasOEM: oem-trust-software 满足副署门槛但不提升 trust
	if tx.Source == SourceDynamicInstall && m.trust.policyRequireOEMCountersign() && !signers.HasOEMCountersign {
		if !dev.Enabled || !dev.SkipOEMCountersign {
			m.auditInstall(ctx, tx, false, ErrOEMCountersignRequired)
			return Entry{}, ErrOEMCountersignRequired
		}
		m.aud.Record(ctx, audit.Event{
			Action: "pkgregistry.Install.devmode", Subject: manifest.PackageID,
			Detail: "relaxed: skip_oem_countersign",
		})
	}

	// ---- Host ABI 匹配 (fresh 与 upgrade 都要) ----
	if err := checkHostABI(manifest.SupportedABIs); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	// ---- digest 复核 ----
	diff, err := VerifyDigests(tx.StagingDir, manifest.Digests)
	if err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}
	if !diff.Clean() {
		err := fmt.Errorf("%w: %+v", ErrDigestMismatch, diff)
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	provider, err := loadRequiredProviderArtifacts(tx.StagingDir, manifest)
	if err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	// ---- 升级裁决 (必须在任何写状态之前读到 prev) ----
	prev, hadPrev := m.readPrevState(manifest.PackageID)
	var carriedDisabled []string
	if hadPrev {
		if prev.RemovalPending {
			err := fmt.Errorf("%w: %q", ErrPackageRemovalPending, manifest.PackageID)
			m.auditInstall(ctx, tx, false, err)
			return Entry{}, err
		}
		if err := checkUpgrade(prev, manifest, signers, dev); err != nil {
			m.auditInstall(ctx, tx, false, err)
			return Entry{}, err
		}
		carriedDisabled = prev.DisabledComponents // 停用状态跨升级保留
	}

	entry := Entry{
		Manifest:           manifest,
		ActiveVersion:      manifest.Version,
		VersionCode:        manifest.VersionCode,
		Trust:              trust,
		Source:             tx.Source,
		DisabledComponents: append([]string(nil), carriedDisabled...),
		SignerRoles:        signers.RoleStrings(),
		VerifiedSigners:    append([]VerifiedSigner(nil), signers.VerifiedSigners...),
		provider:           provider,
	}
	if signers.Dev != nil {
		entry.DeveloperRootID = signers.Dev.RootKeyID
	}

	// Validate the complete new catalog and recompute every package grant before
	// allocating a UID, writing the package tree, or updating the ledger.
	prepared, err := m.prepareEntries(ctx, upsertEntry(previousEntries, entry))
	if err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}
	entry, ok := findEntry(prepared.entries, manifest.PackageID)
	if !ok {
		err := fmt.Errorf("pkgregistry: prepared entry %q disappeared", manifest.PackageID)
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	uid, err := stableUID(m.stateDir, manifest.PackageID, manifest.Version, trust, tx.Source)
	if err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}
	entry.UID = uid
	for i := range prepared.entries {
		if prepared.entries[i].Manifest.PackageID == manifest.PackageID {
			prepared.entries[i].UID = uid
			break
		}
	}
	subj := authority.Subject{PackageID: manifest.PackageID, UID: uid}

	destDir := filepath.Join(m.packageRoot, manifest.PackageID, manifest.Version)
	// 同版本重装 (修复损坏安装) 必须显式要求覆盖. checkUpgrade 上面已经放行了
	// 这种情况, 但 authority 默认用 RENAME_NOREPLACE 拒绝一切已存在的目标 -
	// 不把这个意图说出口, 那条策略就交付不了, 装包以裸 renameat2 EEXIST 失败.
	//
	// 判据用 ActiveVersion 而不是 VersionCode: 撞车的是路径
	// <PackageRoot>/<id>/<version>, 而路径由版本字符串决定. 同一个 version_code
	// 配不同 version 字符串是畸形 manifest, 但那该由 manifest 校验拦,
	// 不该让这里因为判错而去覆盖一个不该覆盖的目录
	replacing := hadPrev && prev.ActiveVersion == manifest.Version
	if err := m.auth.InstallVerifiedPackage(ctx, subj, authority.InstallVerifiedPackageRequest{
		StagingDir:      tx.StagingDir,
		DestDir:         destDir,
		ReplaceExisting: replacing,
	}); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	// 失败补偿: InstallVerifiedPackage 已把代码落盘 (RENAME_NOREPLACE 保证 destDir
	// 是本次新建), 此后任一步失败都会留下一个盘上有代码, Registry 里没有的孤儿
	// 目录, 且下次同版本重装会撞 RENAME_NOREPLACE 永远修不好. committed 在 commit 成功
	// 后置真; 否则本闭包删掉刚落盘的代码目录 (升级场景删的是新版本目录, 旧版本不动)
	committed := false
	newDataDir := ""
	defer func() {
		if committed {
			return
		}
		// 覆盖安装不删代码目录. 那种场景下 destDir 是这个包唯一的代码
		// 目录 - 旧树在 RENAME_EXCHANGE 时被换出并删掉了. 删了就得到"记账说
		// 装着 version X, 盘上什么都没有", 比不回滚糟得多.
		//
		// 不删是安全的: destDir 里那棵树已经过完整的签名与 digest 复核, 而
		// 记账仍指向 version X - 记账与磁盘一致, 只是内容换成了新提交的那份.
		// 而重装的前提本就是旧的那份坏了.
		if !replacing {
			if rerr := m.auth.RemovePackageTree(ctx, subj, authority.RemovePackageTreeRequest{
				Root: m.packageRoot, Path: destDir,
			}); rerr != nil {
				m.aud.Record(ctx, audit.Event{
					Action: "pkgregistry.Install.compensate", Subject: manifest.PackageID, Denied: true, Err: rerr,
				})
			}
		}
		if newDataDir != "" {
			_ = m.auth.RemovePackageTree(ctx, subj, authority.RemovePackageTreeRequest{
				Root: m.dataRoot, Path: newDataDir,
			})
		}
	}()

	// 系统用户必须每次安装都确保, 不能只在!hadPrev 时做.
	//
	// 它与数据目录不同: 数据目录是本机状态, 建了就一直在; 而 /etc/passwd 可能
	// 被镜像 OTA 换掉, 被运维手工清理, 或者这个包本来就是在别处装好后随
	// 记账文件恢复过来的. EnsureAppUser 幂等 (条目在就什么都不做), 无条件调
	// 的成本是一次文件读, 漏调的代价是这个包的组件永远起不来 (217/USER).
	//
	// 放在数据目录之前: 目录的属主是这个 UID, 用户先在, 属主才是有名字的.
	if err := m.auth.EnsureAppUser(ctx, subj, authority.EnsureAppUserRequest{
		UID: uid, GID: uid, Name: authority.AppUserName(uid),
	}); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	// 私有数据目录是 per-package (不是 per-version), 升级不动它 - 它在首次
	// 安装时创建, 跨升级保留. 升级时若无条件再建一次, Linux mkdirat 会 EEXIST
	// 失败, 拖垮整条升级 (ops.go 的 osCreateDataDir). 因此只在全新安装时创建
	if !hadPrev {
		dataDir := filepath.Join(m.dataRoot, manifest.PackageID)
		if _, err := m.auth.CreatePrivateDataDirectory(ctx, subj, authority.CreateDataDirRequest{
			Path: dataDir, UID: uid, GID: uid, Perm: 0o700,
		}); err != nil {
			m.auditInstall(ctx, tx, false, err)
			return Entry{}, err
		}
		newDataDir = dataDir // 本次新建, 补偿时一并回滚
	}

	st := registryState{
		PackageID: manifest.PackageID, ActiveVersion: manifest.Version, VersionCode: manifest.VersionCode,
		UID: uid, Trust: trust.String(), Source: tx.Source.String(),
		GrantedPermissions: entry.GrantedPermissions, DisabledComponents: carriedDisabled,
	}
	if signers.Dev != nil {
		st.LineageRootKeyID = signers.Dev.RootKeyID
		st.LineageKeyIDs = signers.Dev.KeyIDs
	}
	if err := saveRegistryState(m.stateDir, st); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	if err := m.publishCatalogLast(ctx, previousEntries, prepared); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}
	committed = true // commit 成功: 不再补偿删除

	// 默认授予必须在 commit 之后落: SetRuntimeState 要求权限已经在安装期
	// 授予集合里, 而那个集合是上面 publishCatalogLast 里的 perm.Replace 才推
	// 上去的. 早一步调用一律得到 "no installed grant"
	m.applyInstallConsent(ctx, entry, prepared.candidate.Snapshot())
	// A successful upgrade or same-version replacement invalidates every route
	// and stream authorized by the old package generation. Revoke after the
	// catalog commit (a failed pre-commit install must not disturb the live
	// version) and before asking service.Manager to reload the processes.
	if hadPrev && m.transferRevoker != nil {
		m.transferRevoker.RevokePackage(manifest.PackageID)
	}

	// 升级: 把运行中的旧版本组件切到新版本. 否则旧版本继续运行, 崩溃后还被按旧
	// Entry 重启 (升级修复). ReloadPackage 会先停旧实例再起新版本, 共享 unit
	// 名的起/停不竞态. stopper 未接线 (nil) 时跳过 - 那时也没有在跑的组件
	if hadPrev && m.stopper != nil {
		if rerr := m.stopper.ReloadPackage(ctx, manifest.PackageID); rerr != nil {
			m.aud.Record(ctx, audit.Event{
				Action: "pkgregistry.Install.reload", Subject: manifest.PackageID, Denied: true, Err: rerr,
			})
			err := fmt.Errorf("%w: %w", ErrReloadPending, rerr)
			m.auditInstall(ctx, tx, false, err)
			return entry, err
		}
	}

	m.auditInstall(ctx, tx, true, nil)
	return entry, nil
}

// applyInstallConsent 把本包申请到的 USER_CONSENT 权限落成运行期 Granted.
//
// # 为什么是"默认给"而不是"问过才给"
//
// USER_CONSENT 权限的运行期状态默认是 NOT_REQUESTED, 而应用【没有】请求权限的
// API. 于是在有安装确认屏之前, 一个普通应用申请的敏感权限【永远】拿不到 ——
// 应用无法自救, 用户也没有界面可批, 症状是功能静默不工作.
//
// 本系统的选择是装完即给, 用户之后可在权限管理界面逐条关掉:
//
//	装完      -> 申请到的 USER_CONSENT 权限直接 Granted, 应用即刻可用
//	不想给    -> 设置 → 权限, 关掉哪条哪条立即失效 (ACL 与路由都会热更新)
//	被关掉后  -> 应用可以再发起一次动态申请, 由用户当场决定
//
// 【这是一个明确的取舍, 不是疏忽】. 代价是应用装上那一刻就拿到了它申请的全部
// 敏感能力 (包括运动控制), 用户是事后知情而不是事前同意. 换来的是权限系统从
// "全都拿不到"变成"全都能用且可撤销" —— 前者不是更安全, 只是让敏感功能整体不
// 可用, 而不可用的功能不会有人去关它.
//
// # 仍然只认两者的交集
//
// 落库的是 entry.GrantedPermissions ∩ USER_CONSENT:
//
//	不在 GrantedPermissions 里 -> 安装期裁决压根没批 (信任不够, 签名角色不对,
//	                              或来源不是系统镜像). 默认给不能凭空补上
//	不是 USER_CONSENT         -> 它没有"运行期状态"这回事: NORMAL 装上即生效,
//	                              PRIVILEGED/SYSTEM_ONLY 由来源与签名决定.
//	                              写进去只会从 SetRuntimeState 拿回一个错误
//
// # 升级不覆盖用户的既有决定
//
// 卸载才清 _grants.json (ClearPackage 只在卸载路径调用), 升级不清. 因此重装时
// 上一次的决定还在, 而【用户明确关掉的权限绝不能因为一次版本更新被重新打开】——
// 那等于给每个应用一条绕过用户决定的路: 发个新版本就把权限拿回来.
//
// 所以只对 NOT_REQUESTED (从没被决定过) 的那些默认给. Denied /
// DeniedPermanent 一律跳过, 已经是 Granted 的也不必再写一次.
//
// # 失败为什么不回滚安装
//
// 走到这里包已经 commit 了. 一条权限没落上, 用户在设置里再点一次即可; 反过来
// 为它把装好的包整个回滚, 代价与收益不成比例. 但必须留审计 - 否则用户会看到
// 一个"装上了却没生效"的权限, 而系统里没有任何痕迹解释为什么
func (m *Module) applyInstallConsent(
	ctx context.Context, entry Entry, snap *catalog.Snapshot,
) {
	if m.perm == nil || snap == nil {
		return
	}
	for _, permissionID := range entry.GrantedPermissions {
		definition, ok := snap.Permission(permissionID)
		if !ok || definition.GrantMode != ipcv1.GrantMode_GRANT_MODE_USER_CONSENT {
			continue
		}
		// 见上面"升级不覆盖用户的既有决定": 只给从没被决定过的那些
		if state := m.perm.GrantStateOf(entry.Manifest.PackageID, permissionID); state != permission.GrantStateNotRequested {
			m.aud.Record(ctx, audit.Event{
				Action:  "pkgregistry.Install.defaultGrant.kept",
				Subject: entry.Manifest.PackageID,
				Detail:  fmt.Sprintf("%s state=%v", permissionID, state),
			})
			continue
		}
		if err := m.perm.SetRuntimeState(
			entry.Manifest.PackageID, permissionID, permission.GrantStateGranted,
		); err != nil {
			m.aud.Record(ctx, audit.Event{
				Action:  "pkgregistry.Install.defaultGrant",
				Subject: entry.Manifest.PackageID,
				Denied:  true,
				Err:     err,
				Detail:  permissionID,
			})
		}
	}
}

// readPrevState 读取某 Package 已装版本的持久化记账; 无则第二返回值为 false
func (m *Module) readPrevState(packageID string) (registryState, bool) {
	sp, err := stateFilePath(m.stateDir, packageID)
	if err != nil {
		return registryState{}, false
	}
	st, err := readRegistryState(sp)
	if err != nil {
		return registryState{}, false
	}
	return st, true
}

func (m *Module) auditInstall(ctx context.Context, tx InstallTransaction, ok bool, err error) {
	m.aud.Record(ctx, audit.Event{
		Action: "pkgregistry.Install", Subject: tx.Source.String(), Denied: !ok, Err: err,
	})
}
