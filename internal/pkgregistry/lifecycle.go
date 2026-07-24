// 本文件实现卸载与停用或启用，并与 install.go 共用 Module.mu
// 串行化，保证卸载/停用与安装不并发交错、三份投影不分裂。
package pkgregistry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
)

var (
	// ErrPackageNotInstalled 卸载/停用一个未安装的 Package
	ErrPackageNotInstalled = errors.New("pkgregistry: package not installed")
	// ErrComponentNotFound 目标 Component 不在该 Package 的 manifest 中
	ErrComponentNotFound = errors.New("pkgregistry: component not found")
	// ErrComponentProtected 目标 Component 在保护名单里或声明为不可停用，拒绝停用
	ErrComponentProtected = errors.New("pkgregistry: component cannot be disabled")
	// ErrSystemPackageImmutable 系统镜像来源的 Package 不能被动态卸载（跟随整镜像 OTA）
	ErrSystemPackageImmutable = errors.New("pkgregistry: system-image package cannot be uninstalled")
)

// isProtectedComponent 报告 "<pkg>/<comp>" 是否在编译期硬编码的不可停用名单里
// 。理由同 permission.DefaultCatalog：这条底线不能由文件系统写
// 权限决定，所以是代码里的 switch 而非可被改动的数据。停用提供停用 UI 的设置 app
// 自身、权限确认通道、会话/包管理/安全恢复，都会让系统失去自我修复能力。用函数而非
// 包级 map，避开 gochecknoglobals，也让名单是代码这件事更直白
func isProtectedComponent(pkgSlashComp string) bool {
	switch pkgSlashComp {
	case "nervus.pkgmanagerd/main",
		"nervus.settings/main",     // 提供停用 UI 的自己不能被停用
		"nervus.permissionui/main", // 权限确认通道不能被停用
		"nervus.sessiond/main",
		"nervus.safety.recovery/main":
		return true
	default:
		return false
	}
}

// CanDisable 报告某 Component 是否可被停用，不可时给出原因
//
// Ordinary 包：用户对自己装的东西有完全控制权，恒可停用（其 manifest 声明
// disableable:false 无效，与 Install 一致）。系统包：不在保护名单、且 manifest 显式
// 声明 disableable:true 才可停
func (e Entry) CanDisable(compID string) (bool, string) {
	if _, ok := e.Manifest.Component(compID); !ok {
		return false, "component not found"
	}
	if e.Trust == identity.TrustOrdinary {
		return true, ""
	}
	if isProtectedComponent(e.Manifest.PackageID + "/" + compID) {
		return false, "protected"
	}
	c, _ := e.Manifest.Component(compID)
	if !c.Disableable {
		return false, "not disableable"
	}
	return true, ""
}

// ComponentStopper 是卸载/停用/升级时对 service.Manager 的窄接口依赖：停掉一个组件
// 的运行实例，或在升级后把整个包切到新版本。为 nil 时跳过（endpoint/service 尚未
// 接线的阶段留接缝）
type ComponentStopper interface {
	StopComponent(ctx context.Context, pkg, comp string) error
	// ReloadPackage 停掉该包全部旧实例并用当前 Registry 的新版本重起 always-on 组件
	// （升级用，防旧版本继续运行/重启）
	ReloadPackage(ctx context.Context, pkg string) error
}

// LeaseRevoker 是卸载/撤权时对 control 的窄接口依赖：撤销某 Package 持有的全部
// ControlLease（若含 motion 则由 control 递增 motion epoch）。为 nil 时跳过（Step 9 接线）
type LeaseRevoker interface {
	RevokeByPackage(pkgID string) error
}

// SetLifecycleHooks 注入卸载/停用需要的外部协作者（service 停组件、control 撤租）。
// 装配期由 main.go 调用；两者都可为 nil（对应阶段未接线时留接缝）
func (m *Module) SetLifecycleHooks(stopper ComponentStopper, revoker LeaseRevoker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopper = stopper
	m.revoker = revoker
}

// SetComponentEnabled 停用/启用一个 Component 并持久化
//
// 停用生效范围（缺一不可，本函数负责持久化 + 投影 + 停运行实例；IPC 握手据
// DisabledComponents 拒绝该组件由 ipc/verifyComponent 侧完成）：
//   - 更新 registryState.DisabledComponents 并原子落盘
//   - Replace 三份投影（DisabledComponents 进 Entry，scan 重启后仍生效）
//   - 停掉运行实例（经 ComponentStopper）
//
// 停用按 Component，不回收 Package UID。启用永远可逆
func (m *Module) SetComponentEnabled(ctx context.Context, pkgID, compID string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.registry.Lookup(pkgID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrPackageNotInstalled, pkgID)
	}
	if _, ok := e.Manifest.Component(compID); !ok {
		return fmt.Errorf("%w: %s/%s", ErrComponentNotFound, pkgID, compID)
	}

	if !enabled {
		if can, why := e.CanDisable(compID); !can {
			err := fmt.Errorf("%w: %s/%s (%s)", ErrComponentProtected, pkgID, compID, why)
			m.aud.Record(ctx, audit.Event{Action: "pkgregistry.SetComponentEnabled", Subject: pkgID, Denied: true, Err: err})
			return err
		}
	}

	// 计算新的 DisabledComponents 集合
	next := setMembership(e.DisabledComponents, compID, !enabled)

	// 持久化：先落盘记账，再 Replace 内存投影（落盘失败就不动内存态）
	st, ok := m.readState(pkgID)
	if !ok {
		return fmt.Errorf("%w: %q (no ledger)", ErrPackageNotInstalled, pkgID)
	}
	st.DisabledComponents = next
	if err := saveRegistryState(m.stateDir, st); err != nil {
		return err
	}

	e.DisabledComponents = next
	if err := m.replaceEntry(e); err != nil {
		return err
	}

	// 停用：停掉运行实例（启用则交给下一次 Start/EnsureStarted 拉起，本函数不主动起）
	if !enabled && m.stopper != nil {
		if err := m.stopper.StopComponent(ctx, pkgID, compID); err != nil {
			// 停实例失败不回滚持久化的停用意图 - 持久化的 disabled 是权威，实例
			// 会在下次复核/重启时被清；只记审计
			m.aud.Record(ctx, audit.Event{Action: "pkgregistry.SetComponentEnabled.stop", Subject: pkgID, Denied: true, Err: err})
		}
	}

	m.aud.Record(ctx, audit.Event{
		Action: "pkgregistry.SetComponentEnabled", Subject: pkgID,
		Detail: fmt.Sprintf("%s enabled=%v", compID, enabled),
	})
	return nil
}

// Uninstall 彻底删除一个 Package：代码、数据、记账、投影全清，UID 不复用
// （由 allocateUID 的单调高水位保证）。系统镜像来源的包不可动态卸载
func (m *Module) Uninstall(ctx context.Context, pkgID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.registry.Lookup(pkgID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrPackageNotInstalled, pkgID)
	}
	if e.Source == SourceSystemImage {
		return fmt.Errorf("%w: %q", ErrSystemPackageImmutable, pkgID)
	}

	// 1. 停掉该包全部组件的运行实例（接缝：service 未接线时 stopper 为 nil）
	if m.stopper != nil {
		for _, c := range e.Manifest.Components {
			if err := m.stopper.StopComponent(ctx, pkgID, c.ID); err != nil {
				m.aud.Record(ctx, audit.Event{Action: "pkgregistry.Uninstall.stop", Subject: pkgID, Denied: true, Err: err})
			}
		}
	}

	// 2. 撤销其持有的全部 ControlLease（含 motion -> control 递增 epoch）。接缝：Step 9
	if m.revoker != nil {
		if err := m.revoker.RevokeByPackage(pkgID); err != nil {
			m.aud.Record(ctx, audit.Event{Action: "pkgregistry.Uninstall.revoke", Subject: pkgID, Denied: true, Err: err})
		}
	}

	// 3. 从三份投影里剔除该包（全量原子替换，已有范式）
	if err := m.removeEntry(pkgID); err != nil {
		return err
	}

	// 4. 删代码目录与数据目录（经 authority openat2 递归删除）
	subj := authority.Subject{PackageID: pkgID, UID: e.UID}
	codeDir := filepath.Join(m.packageRoot, pkgID)
	if err := m.auth.RemovePackageTree(ctx, subj, authority.RemovePackageTreeRequest{Root: m.packageRoot, Path: codeDir}); err != nil {
		m.aud.Record(ctx, audit.Event{Action: "pkgregistry.Uninstall.rmCode", Subject: pkgID, Denied: true, Err: err})
		return err
	}
	dataDir := filepath.Join(m.dataRoot, pkgID)
	if err := m.auth.RemovePackageTree(ctx, subj, authority.RemovePackageTreeRequest{Root: m.dataRoot, Path: dataDir}); err != nil {
		m.aud.Record(ctx, audit.Event{Action: "pkgregistry.Uninstall.rmData", Subject: pkgID, Denied: true, Err: err})
		return err
	}

	// 5. 删记账文件（nervud 自有 registry 目录，不跨信任边界，走 os；packageID 已
	// 经 stateFilePath 的 validPackageID 二次校验）
	if sp, err := stateFilePath(m.stateDir, pkgID); err == nil {
		if rerr := os.Remove(sp); rerr != nil && !os.IsNotExist(rerr) {
			m.aud.Record(ctx, audit.Event{Action: "pkgregistry.Uninstall.rmLedger", Subject: pkgID, Denied: true, Err: rerr})
		}
	}

	// 6. 清运行期权限授予状态（_grants.json）。install-set 已随 removeEntry 的投影剔除，
	// 但运行期危险权限授予是 permission 单独的持久态，不清会被同 ID 重装继承
	if cerr := m.perm.ClearPackage(pkgID); cerr != nil {
		m.aud.Record(ctx, audit.Event{Action: "pkgregistry.Uninstall.clearGrants", Subject: pkgID, Denied: true, Err: cerr})
	}

	m.aud.Record(ctx, audit.Event{Action: "pkgregistry.Uninstall", Subject: pkgID})
	return nil
}

// ---- 内部辅助 -------------------------------------------------------------

// setMembership 返回把 id 加入(present=true)/移出(present=false) set 后的新切片（去重、稳定）
func setMembership(set []string, id string, present bool) []string {
	out := make([]string, 0, len(set)+1)
	seen := false
	for _, x := range set {
		if x == id {
			seen = true
			if present {
				out = append(out, x) // 保留
			}
			continue
		}
		out = append(out, x)
	}
	if present && !seen {
		out = append(out, id)
	}
	return out
}

// readState 读某包的持久化记账（调用方持 mu）
func (m *Module) readState(pkgID string) (registryState, bool) {
	sp, err := stateFilePath(m.stateDir, pkgID)
	if err != nil {
		return registryState{}, false
	}
	st, err := readRegistryState(sp)
	if err != nil {
		return registryState{}, false
	}
	return st, true
}

// replaceEntry 用改动后的 e 覆盖 Registry 里的同 ID 项，并重投影三份状态（持 mu）
func (m *Module) replaceEntry(e Entry) error {
	entries := m.registry.List()
	for i := range entries {
		if entries[i].Manifest.PackageID == e.Manifest.PackageID {
			entries[i] = e
		}
	}
	return m.commitEntries(entries)
}

// removeEntry 从 Registry 剔除某 ID 后重投影三份状态（持 mu）
func (m *Module) removeEntry(pkgID string) error {
	existing := m.registry.List()
	entries := make([]Entry, 0, len(existing))
	for _, cur := range existing {
		if cur.Manifest.PackageID == pkgID {
			continue
		}
		entries = append(entries, cur)
	}
	return m.commitEntries(entries)
}

// commitEntries 把一组 Entry 全量原子替换进 Registry 并重投影 identity/permission
func (m *Module) commitEntries(entries []Entry) error {
	if err := m.registry.Replace(entries); err != nil {
		return err
	}
	if err := m.idReg.Replace(projectIdentity(entries)); err != nil {
		return err
	}
	return m.perm.Replace(projectGrants(entries))
}
