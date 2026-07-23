// 见 doc.go 的包说明
//
// 本文件把 pkgregistry 接入 kernel.Module 生命周期，并持有 Install（见
// install.go）编排所需的全部依赖。两者共用同一个 Module 类型而不是拆成
// 两个各自持有一份 *Registry 的类型——Registry 是权威状态，只能有一份
package pkgregistry

import (
	"context"
	"log/slog"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
)

// Module 把 pkgregistry 接入 kernel.Module 生命周期，并编排安装事务
//
// Start 只做一次启动扫描（见 scan.go）：建初始 Registry 快照，并把瘦投影
// 推给 identity.Registry。本阶段没有需要监视的后台循环——真正对接
// pkgmanagerd 的装包事务处理循环留给下一步，因此不实现 kernel.FatalReporter；
// 等那条循环落地后再评估是否需要
type Module struct {
	auth     PackageInstaller
	idReg    IdentityUpdater
	registry *Registry
	aud      audit.Recorder
	log      *slog.Logger

	stateDir          string // /var/lib/nervus/registry
	systemPackagesDir string // /usr/lib/nervus/system-packages
	packageRoot       string // authority.DefaultInvariants().PackageRoot
	dataRoot          string // authority.DefaultInvariants().DataRoot
}

// New 构造 pkgregistry 的 Module
//
// auth 以窄接口注入（main.go 的装配范式：消费者定义接口，*authority.Gate
// 隐式满足），不把 *authority.Gate 整个传下去。registry 由调用方在装配阶段
// 显式 NewRegistry() 构造后传入，而不是本函数内部 new——如果日后需要在
// Register 之前就单独持有同一个 *Registry（例如给诊断端点只读访问），
// 调用方与 Module 必须共享同一份状态，不能各自持有一份互不知情的副本
func New(
	auth PackageInstaller, idReg IdentityUpdater, registry *Registry, aud audit.Recorder, log *slog.Logger,
	stateDir, systemPackagesDir, packageRoot, dataRoot string,
) *Module {
	return &Module{
		auth: auth, idReg: idReg, registry: registry, aud: aud, log: log,
		stateDir: stateDir, systemPackagesDir: systemPackagesDir,
		packageRoot: packageRoot, dataRoot: dataRoot,
	}
}

func (m *Module) Name() string { return "pkgregistry" }

// Start 执行一次启动扫描，把结果原子装载进 Registry，并投影给 identity
//
// 单个 Package 扫描失败只记审计并跳过（见 Scan 的文档），不会让 Start
// 本身返回错误——一个坏包不该拖垮整条内核启动序列。Start 只在 Registry/
// identity 的 Replace 本身失败时才返回错误，那意味着扫描结果自相矛盾
// （如重复 Package ID），属于装配级别的问题
func (m *Module) Start(_ context.Context) error {
	result := Scan(m.stateDir, m.systemPackagesDir, m.packageRoot, m.log)

	for _, s := range result.Skipped {
		m.aud.Record(context.Background(), audit.Event{
			Action: "pkgregistry.Scan", Subject: s.Path, Denied: true, Err: s.Err,
		})
		if m.log != nil {
			m.log.Warn("pkgregistry: skipped package during scan", "path", s.Path, "err", s.Err)
		}
	}

	if err := m.registry.Replace(result.Entries); err != nil {
		return err
	}
	return m.idReg.Replace(projectIdentity(result.Entries))
}

// Stop 纯内存态，没有需要释放的资源——记账文件在装包/卸载时已经原子落盘
func (m *Module) Stop(_ context.Context) error {
	return nil
}

// projectIdentity 把 Registry 的全量状态投影成 identity.Registry 需要的
// 瘦视图：只留 ID/UID/Trust，版本、manifest 等字段留在 pkgregistry 这份
// 权威状态里，不重复（见 identity.Package 的文档说明）
func projectIdentity(entries []Entry) []identity.Package {
	out := make([]identity.Package, 0, len(entries))
	for _, e := range entries {
		out = append(out, identity.Package{ID: e.Manifest.PackageID, UID: e.UID, Trust: e.Trust})
	}
	return out
}
