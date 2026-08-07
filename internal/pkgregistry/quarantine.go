package pkgregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/catalog"
)

// prepareEntriesQuarantining 是【启动扫描专用】的 prepareEntries：Catalog 构建
// 失败时隔离肇事的那一个 source，然后重建，直到干净或无包可隔离。
//
// # 为什么安装与启动必须是两种失败语义
//
// 安装（install.go）走 prepareEntries，保持全有全无：一个新包让 Catalog 构建
// 不出来，正确反应是拒绝这个包，现有系统一点都不该动。
//
// 启动扫描不能这样。Module.Start 的注释承诺「一个坏包不该拖垮整条内核启动
// 序列」，但那条承诺此前只对 Scan 那一层成立——manifest 解析、digest、验签
// 失败会被逐包跳过。Catalog 层的冲突（资源多管理者、接口契约不一致、命名空间
// 越权）却是全有全无的，于是一个配错的厂商包能让【整台机器起不来】。
//
// 这在多 Provider 场景下不是理论风险：两个厂商摄像头服务声明同一个
// (resource_type, stable_role)，Build 就会以 "multiple managers" 失败。
// 机器人不该因为一个摄像头包配错而无法开机。
//
// # 隔离粒度是 source（整个包），不是单条定义
//
// 一个包的 Provider 契约是一个整体：接口、资源、权限互相引用。丢掉其中一条
// 而保留其余，会得到一个「装了但半残」的包——它能起来、能注册一部分 endpoint，
// 却在某个方法上莫名失败。那种状态比「这个包没装」难查得多。
//
// # 内核 bootstrap 永远不会被隔离
//
// bootstrap sources 由 catalog.Registry.Prepare 自己拼进来，不在 entries 里。
// 因此如果肇事者是 nervus.kernel，下面找不到对应 entry，函数直接返回错误 ——
// 内核自带定义有问题属于装配级故障，必须让启动失败，不能降级运行。
func (m *Module) prepareEntriesQuarantining(
	ctx context.Context, entries []Entry,
) (preparedEntries, []Entry, error) {
	remaining := entries
	var quarantined []Entry

	// 每轮至少剔除一个包，因此最多 len(entries) 轮。显式设界而不是 for{}：
	// 一旦将来出现「剔除后仍报同一个包」的 bug，这里会以错误退出而不是死循环
	for round := 0; round <= len(entries); round++ {
		prepared, err := m.prepareEntries(ctx, remaining)
		if err == nil {
			return prepared, quarantined, nil
		}

		var srcErr *catalog.SourceError
		if !errors.As(err, &srcErr) {
			// 不是某个具体 source 的问题（Catalog 不可用、revision 耗尽等）。
			// 隔离任何包都无济于事
			return preparedEntries{}, quarantined, err
		}

		next, victim, found := dropEntry(remaining, srcErr.PackageID)
		if !found {
			// 肇事者不在我们能剔除的集合里——内核 bootstrap 自身有问题。
			// 这是装配级故障，必须让启动失败
			return preparedEntries{}, quarantined, fmt.Errorf(
				"pkgregistry: catalog rejected non-package source %q: %w", srcErr.PackageID, err)
		}

		m.aud.Record(ctx, audit.Event{
			Action:  "pkgregistry.QuarantinePackage",
			Subject: srcErr.PackageID,
			Denied:  true,
			Err:     srcErr.Err,
			Detail:  "package excluded from catalog at boot; the rest of the system continues",
		})
		if m.log != nil {
			m.log.Error("pkgregistry: package quarantined at boot",
				"package_id", srcErr.PackageID, "err", srcErr.Err)
		}

		quarantined = append(quarantined, victim)
		remaining = next
	}

	return preparedEntries{}, quarantined, errors.New(
		"pkgregistry: catalog still rejected after quarantining every package")
}

// dropEntry 返回剔除 packageID 之后的切片、被剔除的那个 Entry，以及是否找到。
// 不改动入参切片：调用方仍持有原始集合用于审计。
func dropEntry(entries []Entry, packageID string) ([]Entry, Entry, bool) {
	for i, e := range entries {
		if e.Manifest.PackageID != packageID {
			continue
		}
		next := make([]Entry, 0, len(entries)-1)
		next = append(next, entries[:i]...)
		next = append(next, entries[i+1:]...)
		return next, e, true
	}
	return entries, Entry{}, false
}
