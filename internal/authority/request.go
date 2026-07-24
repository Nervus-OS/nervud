// 本文件定义各特权操作的请求类型与导出方法。每个操作 = 一个 XxxRequest
// （Kind + Validate + 可选 Detail）+ 一个只有一行 do(...) 的 Gate 方法
//
// 只落地调用者形状已经确定的操作：
//
//	CreatePrivateDataDirectory / SetOwner / Reboot / InstallVerifiedPackage
//
// 其余 4 个 Kind（PrepareAppIdentity、StartSandboxedProcess、StopProcess、
// EnableFsVerity）的请求形状由各自的第一个真实调用者（identity / service）
// 落地时倒逼出来，现在定义只会是猜测。特别地 StopProcess 必须等 service 定型：
// 裸 PID 有复用竞态（PID 被回收后杀错进程），正解是 service 在 spawn 时持有
// pidfd、Authority 对 pidfd 发信号 - 那会直接改变请求字段。EnableFsVerity
// 同样推迟：fs-verity 属于加固而非 v1 装包主链路的阻断项
package authority

import (
	"context"
	"fmt"
)

// ---- CreatePrivateDataDirectory ------------------------------------------

// CreateDataDirRequest 创建一个 App 私有数据目录
// 父目录必须已存在：不做 MkdirAll - 每一级目录的创建都应是一次显式的特权操作
type CreateDataDirRequest struct {
	Path string // 必须位于 Invariants.DataRoot 之下（斜杠分隔的 Linux 绝对路径）
	UID  uint32 // 属主，必须落在 App UID 段
	GID  uint32
	Perm uint32 // 如 0o700；不得对 group/other 开放
}

func (CreateDataDirRequest) Kind() Kind { return KindCreatePrivateDataDir }

func (r CreateDataDirRequest) Detail() string { return r.Path }

func (r CreateDataDirRequest) Validate(inv *Invariants) error {
	if err := inv.CheckContained(r.Path, inv.DataRoot); err != nil {
		return err
	}
	if err := inv.CheckUID(r.UID); err != nil {
		return err
	}
	if err := inv.CheckUID(r.GID); err != nil {
		return err
	}
	// 私有数据目录不得对 group/other 开放：这是私有的定义本身，非策略选择
	if r.Perm&0o077 != 0 {
		return fmt.Errorf("%w: perm %#o exposes private data dir to group/other",
			ErrInvariantViolated, r.Perm)
	}
	return nil
}

// DirHandle 是已创建目录的句柄。刻意不暴露裸 fd -
// 裸 fd 传出包外后任何模块都能对它 write/mmap，Gate 就白设了
type DirHandle struct{ Path string }

func (g *Gate) CreatePrivateDataDirectory(
	ctx context.Context, subj Subject, req CreateDataDirRequest,
) (DirHandle, error) {
	return do(ctx, g, subj, req, g.osCreateDataDir)
}

// ---- SetOwner -------------------------------------------------------------

// SetOwnerRequest 修改 DataRoot 内单个路径的属主（非递归；符号链接本身不跟随）
type SetOwnerRequest struct {
	Path string // 必须位于 Invariants.DataRoot 之下
	UID  uint32
	GID  uint32
}

func (SetOwnerRequest) Kind() Kind { return KindSetOwner }

func (r SetOwnerRequest) Detail() string { return r.Path }

func (r SetOwnerRequest) Validate(inv *Invariants) error {
	if err := inv.CheckContained(r.Path, inv.DataRoot); err != nil {
		return err
	}
	if err := inv.CheckUID(r.UID); err != nil {
		return err
	}
	return inv.CheckUID(r.GID)
}

func (g *Gate) SetOwner(ctx context.Context, subj Subject, req SetOwnerRequest) error {
	_, err := do(ctx, g, subj, req, g.osSetOwner)
	return err
}

// ---- Reboot ---------------------------------------------------------------

// RebootRequest 重启整机。正常的故障恢复路径是 fail-fast 退出 + systemd 重启
// nervud（StartLimitAction=reboot 兜底）；本操作留给确需主动重启整机的场景
// （如系统更新提交）
type RebootRequest struct {
	Reason string // 必填：无理由的重启不接受，审计必须能回答为什么
}

func (RebootRequest) Kind() Kind { return KindReboot }

func (r RebootRequest) Detail() string { return r.Reason }

func (r RebootRequest) Validate(*Invariants) error {
	if r.Reason == "" {
		return fmt.Errorf("%w: reboot without a reason is not accepted", ErrInvariantViolated)
	}
	return nil
}

func (g *Gate) Reboot(ctx context.Context, subj Subject, req RebootRequest) error {
	_, err := do(ctx, g, subj, req, g.osReboot)
	return err
}

// ---- InstallVerifiedPackage -------------------------------------------

// InstallVerifiedPackageRequest 把已经完成签名、digest 和权限裁决的 staging
// 目录原子提交为最终只读代码目录，避免 Authority 重复实现包验证
//
// 本请求只做"移动 + 收紧顶层属主"，不做压缩/展开/复核 - 压缩展开是
// pkgmanagerd 的职责，复核是 pkgregistry 的职责，Authority 只负责这一步
// 唯一有权跨越信任边界的落盘动作
//
// 故意不带 UID/GID 字段：最终代码目录的属主是 nervud 自身（见 ops.go 的
// finishInstalledPackage），不是该 Package 的 App UID - 只读代码目录必须
// 让"谁也不能是自己代码的属主"这条底线成立，把属主设成 App UID 反而会让
// 被攻破的 App 有能力 chmod 回可写、修改自己的可执行代码
type InstallVerifiedPackageRequest struct {
	StagingDir string // pkgmanagerd 产出、已被 pkgregistry 复核过的 staging 目录
	DestDir    string // 必须位于 Invariants.PackageRoot 之下：<PackageRoot>/<id>/<version>
}

func (InstallVerifiedPackageRequest) Kind() Kind { return KindInstallVerifiedPackage }

func (r InstallVerifiedPackageRequest) Detail() string { return r.DestDir }

func (r InstallVerifiedPackageRequest) Validate(inv *Invariants) error {
	if err := inv.CheckContained(r.DestDir, inv.PackageRoot); err != nil {
		return err
	}
	if r.StagingDir == "" {
		return fmt.Errorf("%w: empty staging dir", ErrInvariantViolated)
	}
	return nil
}

func (g *Gate) InstallVerifiedPackage(ctx context.Context, subj Subject, req InstallVerifiedPackageRequest) error {
	_, err := do(ctx, g, subj, req, g.osInstallVerifiedPackage)
	return err
}
