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

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
)

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
	return nil
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
