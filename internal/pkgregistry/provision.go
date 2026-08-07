// 本文件补齐 Package 的【运行前置】：系统用户与私有数据目录。
//
// # 为什么单独一个文件
//
// 这两件事此前只在动态安装路径（install.go）上做，而系统镜像包走的是
// scanSystemImage —— 它分配 UID、登记 Entry，却从不建用户也不建数据目录。
// 结果是系统包在一台干净机器上【永远起不来】：
//
//	没有 passwd 条目 → systemd 在 step USER 失败，217/USER
//	没有数据目录     → systemd 在 step NAMESPACE 失败，226/NAMESPACE
//	                   （WorkingDirectory 与 ReadWritePaths 都指向它）
//
// 两条都是真实撞到的，不是理论推演。
//
// 把它抽出来是为了让「一个包要能跑起来，系统上必须存在什么」有一个明确的
// 单一落点，而不是散在安装流程的两个分支里各做一半。
package pkgregistry

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
)

// PermissionStorageShared 是服务间共享区的门槛。与中央 catalog bootstrap 里的
// 条目【必须同名】——那边是定义，这边决定要不要给这个包建目录。
const PermissionStorageShared = "perm.storage.shared"

// provisionEntry 确保 e 对应的系统用户与私有数据目录存在。幂等。
//
// 单个包失败【不阻断其它包】：一个包的用户建不出来不该让整机起不来。失败会
// 记审计并返回错误，由调用方决定怎么记；那个包的组件随后会在 systemd 侧失败，
// 由 service 的监督链按 criticality 处置——那条路径本来就是为「组件起不来」
// 准备的。
func (m *Module) provisionEntry(ctx context.Context, e Entry) error {
	subj := authority.Subject{PackageID: e.Manifest.PackageID, UID: e.UID}

	// 1. 系统用户。GID 恒等于 UID（见 service.buildStartReq 的 GID: e.UID）。
	if err := m.auth.EnsureAppUser(ctx, subj, authority.EnsureAppUserRequest{
		UID:  e.UID,
		GID:  e.UID,
		Name: authority.AppUserName(e.UID),
	}); err != nil {
		return fmt.Errorf("ensure app user for %s: %w", e.Manifest.PackageID, err)
	}

	// 2. 私有数据目录。per-package 不是 per-version —— 升级不动它。
	//
	// 已存在时 CreatePrivateDataDirectory 会以 EEXIST 失败，那在这里是【正常
	// 情况】而不是错误：本函数在每次启动扫描时对每个包都跑一遍。
	dataDir := filepath.Join(m.dataRoot, e.Manifest.PackageID)
	_, err := m.auth.CreatePrivateDataDirectory(ctx, subj, authority.CreateDataDirRequest{
		Path: dataDir, UID: e.UID, GID: e.UID, Perm: 0o700,
	})
	if err != nil && !errors.Is(err, authority.ErrAlreadyExists) {
		return fmt.Errorf("ensure data dir for %s: %w", e.Manifest.PackageID, err)
	}

	// 3. 服务间共享区的两个子目录。【只给申请了 perm.storage.shared 的包建】。
	//
	// 为什么由内核建而不是让服务自己 mkdir：让服务自己建就要求根可写，那样任何
	// 包都能【抢先创建别人的目录名】——恶意包先建 nervus.camerad/ 并占为己有，
	// camerad 起来时发现自己的路径写不进去。sticky 位防的是「删别人的」，
	// 防不了「抢先占名」。根保持 nervud 独占可写，这条攻击就不存在。
	//
	// 为什么按需而不是都建：多数服务用不上共享区。给每个包都建等于在 tmpfs 上
	// 白占一批 inode，还让 ls 出来的目录列表与「谁真的在用」对不上。
	//
	// 【0755 而不是 0700】：这正是「谁都能读、只有属主能写」的语义，共享区存在
	// 的全部意义就在这里。不用 0777——写权限敞开给所有人的话，任何包都能篡改
	// 别人放出来的配置或模型。
	//
	// 无条件重建（而不是像数据目录那样只在首装时建）：SharedRuntimeRoot 在
	// tmpfs 上，每次重启都是空的，不在启动扫描里补齐的话服务第一次写就 ENOENT。
	for _, shared := range m.sharedDirsFor(e) {
		_, err := m.auth.CreatePrivateDataDirectory(ctx, subj, authority.CreateDataDirRequest{
			Path: shared, UID: e.UID, GID: e.UID, Perm: 0o755,
		})
		if err != nil && !errors.Is(err, authority.ErrAlreadyExists) {
			return fmt.Errorf("ensure shared dir %s for %s: %w", shared, e.Manifest.PackageID, err)
		}
	}
	return nil
}

// sharedDirsFor 给出该包在共享区里需要被创建的子目录。
//
// 返回空的三种情况，都不是错误：
//   - 共享区未启用（根为空）——最小装配与大量测试
//   - 该包没申请 perm.storage.shared——多数服务用不上共享区
//   - 申请了但没被授予——权限裁决说了不算数
//
// 判据用 GrantedPermissions 而不是 manifest.Permissions：前者是内核裁决后的
// 结论，后者只是申请。按申请建目录等于让任何包写一行 manifest 就占一个位置。
func (m *Module) sharedDirsFor(e Entry) []string {
	if !slices.Contains(e.GrantedPermissions, PermissionStorageShared) {
		return nil
	}
	var out []string
	if m.sharedRuntimeRoot != "" {
		out = append(out, filepath.Join(m.sharedRuntimeRoot, e.Manifest.PackageID))
	}
	if m.sharedPersistRoot != "" {
		out = append(out, filepath.Join(m.sharedPersistRoot, e.Manifest.PackageID))
	}
	return out
}

// provisionAll 对全部已装 Package 补齐运行前置，返回成功的数量。
func (m *Module) provisionAll(ctx context.Context, entries []Entry) int {
	ok := 0
	for _, e := range entries {
		if err := m.provisionEntry(ctx, e); err != nil {
			m.aud.Record(ctx, audit.Event{
				Action: "pkgregistry.Provision", Subject: e.Manifest.PackageID,
				Denied: true, Err: err,
			})
			if m.log != nil {
				// WARN 而不是 ERROR：内核照常起来，只是这个包的组件会起不来。
				// 用 ERROR 会让运维以为内核本身出了问题。
				m.log.Warn("pkgregistry: failed to provision package runtime prerequisites",
					"package_id", e.Manifest.PackageID, "err", err)
			}
			continue
		}
		ok++
	}
	return ok
}
