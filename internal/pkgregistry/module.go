// 本文件把 pkgregistry 接入 kernel.Module 生命周期, 并持有 Install (见
// install.go) 编排所需的全部依赖. 两者共用同一个 Module 类型而不是拆成
// 两个各自持有一份 *Registry 的类型 - Registry 是权威状态, 只能有一份
package pkgregistry

import (
	"context"
	"log/slog"
	"sync"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

// Module 把 pkgregistry 接入 kernel.Module 生命周期, 并编排安装事务
//
// Start 只做一次启动扫描 (见 scan.go): 建初始 Registry 快照, 并把瘦投影
// 推给 identity.Registry. 本阶段没有需要监视的后台循环 - 真正对接
// pkgmanagerd 的装包事务处理循环留给下一步, 因此不实现 kernel.FatalReporter;
// 等那条循环落地后再评估是否需要
type Module struct {
	auth        PackageInstaller
	idReg       IdentityUpdater
	perm        PermissionArbiter
	registry    *Registry
	definitions *catalog.Registry
	trust       TrustStore
	aud         audit.Recorder
	log         *slog.Logger

	stateDir          string // /var/lib/nervus/registry
	systemPackagesDir string // /usr/lib/nervus/system-packages
	packageRoot       string // authority.DefaultInvariants.PackageRoot
	dataRoot          string // authority.DefaultInvariants.DataRoot
	// 服务间共享区的两个根. 空值表示不启用 (测试与最小装配).
	// 每个包在其下有一个属主为自己, 0755 的子目录, 见 provisionEntry.
	sharedRuntimeRoot string // authority.DefaultInvariants.SharedRuntimeRoot (tmpfs)
	sharedPersistRoot string // authority.DefaultInvariants.SharedPersistRoot (磁盘)

	// mu 串行化全部状态变更 (Install / Uninstall / SetComponentEnabled). 	// 没有它, 并发安装会争抢 UID 分配器 (_allocator.json 的 read-modify-write),
	// 并让 commit 的 List -> Replace 丢更新, 导致 registry/identity/permission 三份投影
	// 分裂. 装包/卸载不是高频路径, 一把大锁足矣
	mu sync.Mutex

	// stopper/revoker 是卸载/停用时的外部协作者 (service 停组件, control 撤租),
	// 经 SetLifecycleHooks 注入; 可为 nil (对应阶段未接线时留接缝). 读写受 mu 保护
	stopper         ComponentStopper
	revoker         LeaseRevoker
	transferRevoker PackageTransferRevoker
}

// New 构造 pkgregistry 的 Module
//
// auth 以窄接口注入 (main.go 的装配范式: 消费者定义接口, *authority.Gate
// 隐式满足), 不把 *authority.Gate 整个传下去. registry 由调用方在装配阶段
// 显式 NewRegistry 构造后传入, 而不是本函数内部 new - 如果日后需要在
// Register 之前就单独持有同一个 *Registry (例如给诊断端点只读访问),
// 调用方与 Module 必须共享同一份状态, 不能各自持有一份互不知情的副本
// trust 是签名验证的信任根视图. 装配时由 main.go 用
// LoadTrustStore 加载; 加载失败 (开发构建缺内嵌根, 或 bundle 验不过) 时传入
// 零值 TrustStore - 此时 developer 自签仍可验证 (公钥内嵌), 但任何 platform/oem
// 角色都因查不到而 fail-closed, 动态安装一律只能拿 Ordinary, 符合验不过就
// fail-closed
func New(
	auth PackageInstaller, idReg IdentityUpdater, perm PermissionArbiter, registry *Registry,
	definitions *catalog.Registry,
	trust TrustStore, aud audit.Recorder, log *slog.Logger,
	stateDir, systemPackagesDir, packageRoot, dataRoot string,
) *Module {
	return &Module{
		auth: auth, idReg: idReg, perm: perm, registry: registry, definitions: definitions,
		trust: trust, aud: aud, log: log,
		stateDir: stateDir, systemPackagesDir: systemPackagesDir,
		packageRoot: packageRoot, dataRoot: dataRoot,
	}
}

// SetSharedRoots 启用服务间共享区. 装配期一次性设置, Start 之后只读.
//
// 与 New 分开而不是加两个形参: New 已有 12 个参数, 而共享区是可选设施 -
// 最小装配与大量测试并不需要它, 让它们被迫传两个空串只会让调用点更难读.
func (m *Module) SetSharedRoots(runtimeRoot, persistRoot string) {
	m.sharedRuntimeRoot = runtimeRoot
	m.sharedPersistRoot = persistRoot
}

func (m *Module) Name() string { return "pkgregistry" }

// Start 执行一次启动扫描, 把结果原子装载进 Registry, 并投影给 identity
//
// 单个 Package 扫描失败只记审计并跳过, 不会让 Start 本身返回错误,
// 因为一个坏包不该拖垮整条内核启动序列. Start 只在 Registry/
// identity 的 Replace 本身失败时才返回错误, 那意味着扫描结果自相矛盾
//
//	(如重复 Package ID), 属于装配级别的问题
func (m *Module) Start(ctx context.Context) error {
	previous := m.registry.List()
	result := Scan(m.stateDir, m.systemPackagesDir, m.packageRoot, m.trust, m.log)

	for _, s := range result.Skipped {
		m.aud.Record(ctx, audit.Event{
			Action: "pkgregistry.Scan", Subject: s.Path, Denied: true, Err: s.Err,
		})
		if m.log != nil {
			m.log.Warn("pkgregistry: skipped package during scan", "path", s.Path, "err", s.Err)
		}
	}

	// 隔离而不是整体失败. Scan 的逐包跳过只覆盖 manifest/digest/验签那一层;
	// Catalog 层的冲突 (资源多管理者, 接口契约不一致, 命名空间越权) 如果也让
	// Start 返回错误, 一个配错的厂商包就能让整台机器起不来 - 那与本函数注释
	// 承诺的"一个坏包不该拖垮内核启动"直接矛盾.
	//
	// 安装路径 (install.go) 不走这里, 保持全有全无: 新包有问题就拒绝新包.
	prepared, quarantined, err := m.prepareEntriesQuarantining(ctx, result.Entries)
	if err != nil {
		return err
	}
	if len(quarantined) != 0 && m.log != nil {
		ids := make([]string, 0, len(quarantined))
		for _, e := range quarantined {
			ids = append(ids, e.Manifest.PackageID)
		}
		m.log.Error("pkgregistry: boot continued without quarantined packages",
			"count", len(ids), "packages", ids)
	}

	// 补齐运行前置: 系统用户 + 私有数据目录.
	//
	// 必须在这里, 不能只在 install.go 里做. 系统镜像包走 scanSystemImage,
	// 那条路径分配 UID, 登记 Entry, 却从不建用户也不建数据目录 - 于是系统包
	// 在一台干净机器上永远起不来 (217/USER 与 226/NAMESPACE).
	//
	// 放在 Replace 之前: 投影推出去之后 service 模块随时可能拿它去拉进程,
	// 那时前置必须已经就位.
	if n := m.provisionAll(ctx, prepared.entries); m.log != nil {
		m.log.Info("pkgregistry: provisioned package runtime prerequisites",
			"ok", n, "total", len(prepared.entries))
	}
	return m.publishCatalogLast(ctx, previous, prepared)
}

// Stop 纯内存态, 没有需要释放的资源 - 记账文件在装包/卸载时已经原子落盘
func (m *Module) Stop(_ context.Context) error {
	return nil
}

// projectIdentity 把 Registry 的全量状态投影成 identity.Registry 需要的
// 瘦视图: 只留 ID/UID/Trust, 版本, manifest 等字段留在 pkgregistry 这份
// 权威状态里, 避免两个 Registry 各自保存可漂移的副本
func projectIdentity(entries []Entry) []identity.Package {
	out := make([]identity.Package, 0, len(entries))
	for _, e := range entries {
		out = append(out, identity.Package{
			ID: e.Manifest.PackageID, UID: e.UID, Trust: e.Trust,
			Generation: e.RuntimeGeneration,
		})
	}
	return out
}

// projectGrants 把 Registry 的全量状态投影成 permission.Registry 需要的
// 瘦视图: 只留 ID 与已授予权限集合. 与 projectIdentity 同一原则, 这里只把
// prepareEntries 已经基于同一候选 Catalog 重算好的结果投影出去.
func projectGrants(entries []Entry) []permission.Grant {
	out := make([]permission.Grant, 0, len(entries))
	for _, e := range entries {
		out = append(out, permission.Grant{
			PackageID:     e.Manifest.PackageID,
			Permissions:   e.GrantedPermissions,
			ConsentExempt: isSystemSoftware(e),
		})
	}
	return out
}

// isSystemSoftware 判定一个包是否随只读系统镜像发布且受平台信任.
//
// 这类包的 USER_CONSENT 权限不需要运行期同意 (见 permission.Grant.ConsentExempt).
//
// 两个条件都要: 只看 Source 会让一个塞进镜像目录的低信任包蒙混过关; 只看 Trust
// 会让一个动态安装的平台签名包也免掉询问 —— 而"装机时用户已经接受了它"这条
// 理由只对随镜像发布的那批成立
func isSystemSoftware(e Entry) bool {
	return e.Source == SourceSystemImage && e.Trust == identity.TrustPlatform
}
