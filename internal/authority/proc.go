// 本文件是进程生命周期与包树删除三个特权操作的请求契约与 Gate 方法
// （应用层架构决策 §5.1）：
//
//	StartSandboxedProcess  经 systemd StartTransientUnit 起一个沙箱进程
//	StopProcess            停止该 unit
//	RemovePackageTree      递归删除一个已安装 Package 的代码或数据目录（卸载用）
//
// 起进程不由 authority 直接 fork/exec，而是委托 systemd（架构 §8）：sandbox、cgroup
// 限额、UID 降权全部交给 systemd 的 unit 属性，authority 只负责「决定允不允许 +
// 本地不变量校验 + 审计」。真正的 D-Bus 在 internal/authority/systemd 子包。
package authority

import (
	"context"
	"fmt"

	"github.com/nervus-os/nervud/internal/authority/systemd"
)

// PlatformJREExec 是平台内置 JRE 的固定 java 可执行路径（应用层架构决策 §3.6/§5.1）。
// runtime=jvm 的组件，ExecStart 必须【恰好】是它——被校验位置在包内的是 -jar 指向的
// entry 与 native_lib_dir（由 ContainedPaths 承载）
const PlatformJREExec = "/usr/lib/nervus/jre/bin/java"

// Runtime 是进程入口的启动方式。authority 定义自己的小枚举而不 import pkgregistry
// ——pkgregistry 已经 import authority（装包时调 InstallVerifiedPackage），反向依赖
// 会成环。service.Manager 负责把 pkgregistry.Runtime 翻成本类型
type Runtime uint8

const (
	RuntimeNative Runtime = iota
	RuntimeJVM
)

func (r Runtime) valid() bool { return r == RuntimeNative || r == RuntimeJVM }

// ResourceLimits 是组件的资源上限（应用层架构决策 §3.4）。零值表示不设该项。
// 内核按 trust 钳制上限由 service.Manager 负责，authority 只透传
type ResourceLimits struct {
	MemoryMaxBytes  uint64
	CPUQuotaPercent uint32
	TasksMax        uint64
}

// ---- StartSandboxedProcess ------------------------------------------------

// StartSandboxedProcessRequest 请求以瞬态 systemd unit 起一个沙箱进程
type StartSandboxedProcessRequest struct {
	UnitName string  // nervus-<pkgid>-<compid>.service（systemd 侧再白名单校验）
	Desc     string  // 人类可读描述，仅供 systemd status
	Runtime  Runtime // native | jvm
	ExecPath string  // native=包内 ELF；jvm=PlatformJREExec
	Args     []string
	// ContainedPaths 是必须位于 PackageRoot 之内的包内路径（jvm 的 jar、native_lib_dir
	// 等）。Validate 逐一 CheckContained，堵住「java -jar /etc/shadow」这类逃逸
	ContainedPaths    []string
	UID               uint32
	GID               uint32
	WorkingDir        string // 必须位于 DataRoot 之下
	Env               []string
	ReadWritePaths    []string // ProtectSystem=strict 下必须列出可写目录（私有数据目录）
	ReadOnlyPaths     []string
	InaccessiblePaths []string
	Limits            ResourceLimits
	// BindToUnit 非空时给组件 unit 绑定 owner-death：绑定 unit（生产为 nervud.service）
	// 停/failed 即连带停组件，杜绝 nervud 被 SIGKILL 后组件仍归 systemd 持有
	BindToUnit string
}

func (StartSandboxedProcessRequest) Kind() Kind { return KindStartSandboxedProcess }

func (r StartSandboxedProcessRequest) Detail() string { return r.UnitName }

// Validate 按 runtime 分支（应用层架构决策 §5.1 的关键点）：native 的 ExecPath 必须
// 在包内，jvm 的 ExecPath 必须恰好是平台 JRE——否则 jvm 组件永远过不了「exec 在包内」
// 的检查，因为 java 本就在 /usr/lib/nervus/jre 而非包目录
func (r StartSandboxedProcessRequest) Validate(inv *Invariants) error {
	if !r.Runtime.valid() {
		return fmt.Errorf("%w: unknown runtime %d", ErrInvariantViolated, r.Runtime)
	}
	switch r.Runtime {
	case RuntimeNative:
		if err := inv.CheckContained(r.ExecPath, inv.PackageRoot); err != nil {
			return err
		}
	case RuntimeJVM:
		if r.ExecPath != PlatformJREExec {
			return fmt.Errorf("%w: jvm exec must be %q, got %q", ErrInvariantViolated, PlatformJREExec, r.ExecPath)
		}
	}
	// 包内路径（jar / native_lib_dir）必须都在 PackageRoot 之内
	for _, p := range r.ContainedPaths {
		if err := inv.CheckContained(p, inv.PackageRoot); err != nil {
			return err
		}
	}
	// 工作目录必须是该包的私有数据目录（在 DataRoot 之下）
	if err := inv.CheckContained(r.WorkingDir, inv.DataRoot); err != nil {
		return err
	}
	if err := inv.CheckUID(r.UID); err != nil {
		return err
	}
	return inv.CheckUID(r.GID)
}

// ProcessHandle 是一个已启动 unit 的不透明句柄。unit 名不导出——调用方只能把它
// 原样交回 StopProcess/WaitProcess，不能自行构造一个指向任意 unit 的句柄
type ProcessHandle struct{ unit string }

// Unit 返回句柄对应的 systemd unit 名，仅供审计/诊断
func (h ProcessHandle) Unit() string { return h.unit }

func (g *Gate) StartSandboxedProcess(
	ctx context.Context, subj Subject, req StartSandboxedProcessRequest,
) (ProcessHandle, error) {
	return do(ctx, g, subj, req, g.osStartSandboxedProcess)
}

func (g *Gate) osStartSandboxedProcess(ctx context.Context, req StartSandboxedProcessRequest) (ProcessHandle, error) {
	if g.spawner == nil {
		return ProcessHandle{}, fmt.Errorf("%w: no systemd spawner configured", ErrUnsupportedPlatform)
	}
	rt := systemd.RuntimeNative
	if req.Runtime == RuntimeJVM {
		rt = systemd.RuntimeJVM
	}
	_ = rt // systemd.UnitSpec 目前不需要 runtime 区分（ExecStart 已是最终命令）；保留翻译以备扩展
	spec := systemd.UnitSpec{
		Name:        req.UnitName,
		Description: req.Desc,
		ExecPath:    req.ExecPath,
		Args:        req.Args,
		UID:         req.UID,
		GID:         req.GID,
		WorkingDir:  req.WorkingDir,
		Env:         req.Env,
		BindToUnit:  req.BindToUnit,
		Limits: systemd.Limits{
			MemoryMaxBytes:  req.Limits.MemoryMaxBytes,
			CPUQuotaPercent: req.Limits.CPUQuotaPercent,
			TasksMax:        req.Limits.TasksMax,
		},
		Sandbox: systemd.Sandbox{
			ReadWritePaths:    req.ReadWritePaths,
			ReadOnlyPaths:     req.ReadOnlyPaths,
			InaccessiblePaths: req.InaccessiblePaths,
		},
	}
	if err := g.spawner.StartTransientUnit(ctx, spec); err != nil {
		return ProcessHandle{}, err
	}
	return ProcessHandle{unit: req.UnitName}, nil
}

// ---- StopProcess ----------------------------------------------------------

// StopProcessRequest 停止一个此前 StartSandboxedProcess 起的 unit
type StopProcessRequest struct {
	Handle ProcessHandle
}

func (StopProcessRequest) Kind() Kind { return KindStopProcess }

func (r StopProcessRequest) Detail() string { return r.Handle.unit }

func (r StopProcessRequest) Validate(*Invariants) error {
	if r.Handle.unit == "" {
		return fmt.Errorf("%w: empty process handle", ErrInvariantViolated)
	}
	return nil
}

func (g *Gate) StopProcess(ctx context.Context, subj Subject, req StopProcessRequest) error {
	_, err := do(ctx, g, subj, req, g.osStopProcess)
	return err
}

func (g *Gate) osStopProcess(ctx context.Context, req StopProcessRequest) (struct{}, error) {
	if g.spawner == nil {
		return struct{}{}, fmt.Errorf("%w: no systemd spawner configured", ErrUnsupportedPlatform)
	}
	return struct{}{}, g.spawner.StopUnit(ctx, req.Handle.unit)
}

// ---- WaitProcess ----------------------------------------------------------

// ExitInfo 是一个进程到达终态时的退出信息，从 systemd unit 状态翻译而来
type ExitInfo struct {
	Terminal   bool   // 是否已终结（inactive/failed）
	Result     string // systemd Result：success / exit-code / signal / oom-kill / ...
	ExitStatus int
}

// WaitProcess 阻塞直到进程终结，返回退出信息。它是观察操作（不改变系统状态），
// 因此不走 do() 审计流水线——但仍要求 spawner 已配置
func (g *Gate) WaitProcess(ctx context.Context, h ProcessHandle) (ExitInfo, error) {
	if g.spawner == nil {
		return ExitInfo{}, fmt.Errorf("%w: no systemd spawner configured", ErrUnsupportedPlatform)
	}
	if h.unit == "" {
		return ExitInfo{}, fmt.Errorf("%w: empty process handle", ErrInvariantViolated)
	}
	info, err := g.spawner.WaitUnit(ctx, h.unit)
	if err != nil {
		return ExitInfo{}, err
	}
	return ExitInfo{Terminal: info.Terminal(), Result: info.Result, ExitStatus: info.ExitStatus}, nil
}

// ---- RemovePackageTree ----------------------------------------------------

// RemovePackageTreeRequest 递归删除一个已安装 Package 的代码或数据目录（卸载用）
//
// Root 显式说明删的是 PackageRoot 还是 DataRoot——不接受任意 root，避免一个字段
// 就能递归删到 DataRoot/PackageRoot 之外
type RemovePackageTreeRequest struct {
	Root string // 必须【等于】inv.PackageRoot 或 inv.DataRoot
	Path string // 必须位于 Root 之下
}

func (RemovePackageTreeRequest) Kind() Kind { return KindRemovePackageTree }

func (r RemovePackageTreeRequest) Detail() string { return r.Path }

func (r RemovePackageTreeRequest) Validate(inv *Invariants) error {
	// Root 白名单：只能是这两个受管根之一
	if r.Root != inv.PackageRoot && r.Root != inv.DataRoot {
		return fmt.Errorf("%w: remove root %q is neither PackageRoot nor DataRoot", ErrInvariantViolated, r.Root)
	}
	// Path 必须严格在 Root 之内（Root 自身不算——不允许删空整个根）
	return inv.CheckContained(r.Path, r.Root)
}

func (g *Gate) RemovePackageTree(ctx context.Context, subj Subject, req RemovePackageTreeRequest) error {
	_, err := do(ctx, g, subj, req, g.osRemovePackageTree)
	return err
}
