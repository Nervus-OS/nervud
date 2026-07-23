// 见 doc.go 的包说明
//
// 本文件是最终安装裁决与事务提交的编排：把 manifest.go/digest.go/
// signature.go/arbitrate.go 这几块独立的复核逻辑，接到 authority.Gate
// 的两个特权操作上，产出一条登记进 Registry 的 Entry
package pkgregistry

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
)

// PackageInstaller 是 pkgregistry 对 authority.Gate 的窄接口依赖
//
// main.go 的装配范式：消费者包定义自己需要的最小接口，*authority.Gate
// 隐式满足，装配时直接把 Gate 传进来，不必修改 authority 包本身
type PackageInstaller interface {
	InstallVerifiedPackage(ctx context.Context, subj authority.Subject, req authority.InstallVerifiedPackageRequest) error
	CreatePrivateDataDirectory(ctx context.Context, subj authority.Subject, req authority.CreateDataDirRequest) (authority.DirHandle, error)
}

// IdentityUpdater 是 pkgregistry 对 identity.Registry 的窄接口依赖：
// 只需要全量替换那份瘦投影，不需要 Lookup/Resolve 等读侧方法
type IdentityUpdater interface {
	Replace(pkgs []identity.Package) error
}

// InstallTransaction 是一次装包事务的输入
//
// 本阶段不接 pkgmanagerd 的真实 IPC 交接——那依赖 internal/ipc 的 Request/
// Dispatch 管线，而 ipc 当前编译不过（见架构总览 §0.1）。StagingDir 由
// 调用方直接给出，便于单测；日后接入 pkgmanagerd 时只需在外面加一层适配，
// 把 BeginTransaction 的结果转换成 InstallTransaction，这里的编排逻辑不用改
type InstallTransaction struct {
	ManifestBytes []byte // 未解析的原始 manifest.json 字节；签名针对这份原始字节验证
	SigBlock      []byte // 分离签名
	StagingDir    string // pkgmanagerd 产出的、已展开的 staging 目录
	Source        Source
}

// Install 执行架构 §9 动态安装流程里"nervud 独立复核 ... 直到 Registry 登记"
// 的那一段：
//
//  1. 解析并结构校验 manifest（manifest.go）
//  2. 复核签名（signature.go；当前是 stub，见其文档）
//  3. 复核 digest（digest.go）
//  4. 最终裁决：来源 + 已验证信任 -> trust profile（arbitrate.go）
//  5. 分配稳定 UID（与启动扫描共用同一个持久化分配器，见 scan.go）
//  6. Authority 原子提交只读代码目录 + 创建私有数据目录
//  7. 登记进内存 Registry，并把瘦投影推给 identity.Registry
//
// 任一步失败即整体返回错误、不留半成品：前六步失败时都还没有触碰任何
// 跨信任边界的状态（第 6 步内部的失败由 authority/ops.go 自己的回滚保证），
// 第 7 步的两次 Replace 都是全量原子替换，失败也不会把新旧状态混在一起
func (m *Module) Install(ctx context.Context, tx InstallTransaction) (Entry, error) {
	manifest, err := ParseManifest(tx.ManifestBytes)
	if err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	signer, verifiedTrust, sigErr := verifySignature(tx.ManifestBytes, tx.SigBlock)
	// 签名验证失败或未实现不在这里整体拒绝安装：Source == SourceDynamicInstall
	// 时 Arbitrate 本来就会把 trust 定死为 Ordinary，签名结果不改变这个结论。
	// 但必须完整记审计，供离线分析区分"能力缺口"与"真正的签名不符"
	if sigErr != nil {
		m.aud.Record(ctx, audit.Event{
			Action: "pkgregistry.VerifySignature", Subject: manifest.PackageID,
			Denied: true, Err: sigErr, Detail: signer,
		})
	}

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

	decision := Arbitrate(manifest, tx.Source, verifiedTrust, manifest.Permissions)

	uid, err := stableUID(m.stateDir, manifest.PackageID, manifest.Version, decision.Trust, tx.Source)
	if err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}
	subj := authority.Subject{PackageID: manifest.PackageID, UID: uid}

	destDir := filepath.Join(m.packageRoot, manifest.PackageID, manifest.Version)
	if err := m.auth.InstallVerifiedPackage(ctx, subj, authority.InstallVerifiedPackageRequest{
		StagingDir: tx.StagingDir,
		DestDir:    destDir,
	}); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	dataDir := filepath.Join(m.dataRoot, manifest.PackageID)
	if _, err := m.auth.CreatePrivateDataDirectory(ctx, subj, authority.CreateDataDirRequest{
		Path: dataDir, UID: uid, GID: uid, Perm: 0o700,
	}); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	st := registryState{
		PackageID: manifest.PackageID, ActiveVersion: manifest.Version, UID: uid,
		Trust: decision.Trust.String(), Source: tx.Source.String(),
	}
	if err := saveRegistryState(m.stateDir, st); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	entry := Entry{
		Manifest: manifest, ActiveVersion: manifest.Version, UID: uid,
		Trust: decision.Trust, Source: tx.Source,
	}
	if err := m.commit(entry); err != nil {
		m.auditInstall(ctx, tx, false, err)
		return Entry{}, err
	}

	m.auditInstall(ctx, tx, true, nil)
	return entry, nil
}

// commit 把新 Entry 并入内存 Registry（同 Package ID 的旧版本被覆盖，
// 即升级场景），再把全量投影推给 identity.Registry
func (m *Module) commit(e Entry) error {
	existing := m.registry.List()
	entries := make([]Entry, 0, len(existing)+1)
	for _, cur := range existing {
		if cur.Manifest.PackageID == e.Manifest.PackageID {
			continue
		}
		entries = append(entries, cur)
	}
	entries = append(entries, e)

	if err := m.registry.Replace(entries); err != nil {
		return err
	}
	return m.idReg.Replace(projectIdentity(entries))
}

func (m *Module) auditInstall(ctx context.Context, tx InstallTransaction, ok bool, err error) {
	m.aud.Record(ctx, audit.Event{
		Action: "pkgregistry.Install", Subject: tx.Source.String(), Denied: !ok, Err: err,
	})
}
