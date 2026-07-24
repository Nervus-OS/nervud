// Package systemd 是 nervud 对 systemd（Linux PID 1）的 D-Bus 客户端封装
// （nervud 内核与系统服务架构决策 §8）。
//
// 职责边界（架构 §8「systemd D-Bus 客户端依赖」）：
//   - 只允许本子包 import github.com/godbus/dbus/v5：它是对 systemd 的 D-Bus 客户端，
//     属于 TCB。固定精确版本、提交 go.sum、纳入 SBOM。
//   - 对传给 StartTransientUnit 的 unit 名、路径、UID、env、property 做本地白名单
//     校验（见 props.go），禁止调用者传入任意 systemd property。
//   - D-Bus 断开或返回不确定结果时默认失败，不把「请求已发送」当「进程已安全启动」。
//
// 进程生命周期由 systemd 拥有：本封装用瞬态 .service unit 起进程（StartTransientUnit），
// 用 StopUnit 停。这【偏离】§5.1 的 pidfd 草图，是刻意的——unit 名是 reuse-safe 的
// 稳定句柄，systemd 不会像内核回收 PID 那样把 unit 名复用给另一个进程，因此 §5.1 用
// pidfd 想解决的「裸 PID 复用竞态」在 systemd 托管模型下本就不存在。
//
// 【为什么用轮询而非 JobRemoved 信号确认作业完成】：godbus 的共享连接在信号缓冲满时会
// 静默丢弃信号，而 systemd Manager.Subscribe 会引发持续的信号流（尤其在 degraded 系统上），
// 二者叠加会让「等某个 job 的 JobRemoved」既可能因丢信号而卡到超时、又可能让 drain 逻辑
// 陷入活锁。改为在 ctx 界定的超时内轮询 unit 的 ActiveState 直到 active/failed——这既是
// 「不把请求已发送当已启动」的等价（甚至更强：直接确认 unit 真的 active）保证，又对信号
// 投递可靠性零依赖。轮询间隔远小于起停延迟，起停也非高频路径。
package systemd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	dbusDest = "org.freedesktop.systemd1"
	dbusPath = dbus.ObjectPath("/org/freedesktop/systemd1")
	mgrIface = "org.freedesktop.systemd1.Manager"

	// startStopPollInterval 是起停确认的轮询间隔；要快，起停延迟通常在百毫秒级
	startStopPollInterval = 50 * time.Millisecond
	// waitPollInterval 是「等一个长期运行组件退出」的轮询间隔；要省，崩溃检测容忍
	// 秒级延迟，没必要每 50ms 拍一次每个运行中组件的状态
	waitPollInterval = 1 * time.Second
)

// ErrJobFailed unit 起停后进入 failed 态
var ErrJobFailed = errors.New("systemd: unit entered failed state")

// Conn 是一条到 systemd 的 D-Bus 连接
//
// 无信号订阅、无内部可变状态：全部通过带 ctx 的方法调用 + 轮询完成，因此天然并发安全，
// 不需要锁
type Conn struct {
	bus *dbus.Conn
	mgr dbus.BusObject
}

// Dial 连接系统总线
func Dial(_ context.Context) (*Conn, error) {
	bus, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("systemd: connect system bus: %w", err)
	}
	return &Conn{bus: bus, mgr: bus.Object(dbusDest, dbusPath)}, nil
}

// Close 关闭底层 D-Bus 连接
func (c *Conn) Close() error {
	if c == nil || c.bus == nil {
		return nil
	}
	return c.bus.Close()
}

// auxUnit 对应 StartTransientUnit 的 aux 参数类型 a(sa(sv))；nervud 不用附属 unit，
// 始终传空数组，但类型必须对齐才能正确编码
type auxUnit struct {
	Name       string
	Properties []property
}

// StartTransientUnit 以瞬态 .service unit 起一个受沙箱约束的进程，并【轮询确认】
// unit 真正进入 active（或 failed）才返回（架构 §8：不把请求已发送当已启动）
func (c *Conn) StartTransientUnit(ctx context.Context, spec UnitSpec) error {
	props, err := BuildProperties(spec)
	if err != nil {
		return err
	}
	// mode "replace"：同名 unit 残留则替换。aux 为空
	call := c.mgr.CallWithContext(ctx, mgrIface+".StartTransientUnit", 0,
		spec.Name, "replace", props, []auxUnit{})
	if call.Err != nil {
		return fmt.Errorf("systemd: StartTransientUnit %s: %w", spec.Name, call.Err)
	}
	return c.pollUntil(ctx, spec.Name, startStopPollInterval, func(info ExitInfo, exists bool) (bool, error) {
		if !exists {
			// unit 消失：可能是极短命进程起后即退。视作「起过了」，交给 WaitUnit 收尾
			return true, nil
		}
		switch info.ActiveState {
		case "active":
			return true, nil
		case "failed":
			return true, fmt.Errorf("%w: %s (result=%s)", ErrJobFailed, spec.Name, info.Result)
		default:
			return false, nil // activating / reloading：继续轮询
		}
	})
}

// StopUnit 停止一个瞬态 unit（systemd 按 unit 的 KillSignal/TimeoutStopSec 先 SIGTERM
// 后 SIGKILL），轮询确认进入 inactive/failed 或已消失
func (c *Conn) StopUnit(ctx context.Context, name string) error {
	if !validUnitName(name) {
		return fmt.Errorf("%w: %q", ErrInvalidUnitName, name)
	}
	call := c.mgr.CallWithContext(ctx, mgrIface+".StopUnit", 0, name, "replace")
	if call.Err != nil {
		if isNoSuchUnit(call.Err) {
			return nil // 已不存在 = 已停（幂等）
		}
		return fmt.Errorf("systemd: StopUnit %s: %w", name, call.Err)
	}
	return c.pollUntil(ctx, name, startStopPollInterval, func(info ExitInfo, exists bool) (bool, error) {
		if !exists {
			return true, nil
		}
		return info.Terminal(), nil
	})
}

// ExitInfo 是一个 unit 的运行/退出信息快照
type ExitInfo struct {
	ActiveState string // active / activating / inactive / failed / deactivating
	Result      string // systemd Result：success / exit-code / signal / oom-kill / ...
	ExitStatus  int    // ExecMainStatus（进程退出码或信号号）
}

// Terminal 报告 unit 是否处于终态（不再运行）
func (e ExitInfo) Terminal() bool {
	return e.ActiveState == "inactive" || e.ActiveState == "failed"
}

// WaitUnit 阻塞直到 unit 进入终态（inactive/failed）或消失，返回其退出信息。
// 供 service.Manager 的崩溃监视用（等一个长期运行的组件退出）
func (c *Conn) WaitUnit(ctx context.Context, name string) (ExitInfo, error) {
	if !validUnitName(name) {
		return ExitInfo{}, fmt.Errorf("%w: %q", ErrInvalidUnitName, name)
	}
	var last ExitInfo
	err := c.pollUntil(ctx, name, waitPollInterval, func(info ExitInfo, exists bool) (bool, error) {
		if !exists {
			last = ExitInfo{ActiveState: "inactive"}
			return true, nil
		}
		last = info
		return info.Terminal(), nil
	})
	if err != nil {
		return ExitInfo{}, err
	}
	return last, nil
}

// pollUntil 每 interval 读一次 unit 状态并交给 done 判定，直到 done 返回 true
// 或 ctx 结束。done 的第二参 exists=false 表示该 unit 当前不存在
func (c *Conn) pollUntil(ctx context.Context, name string, interval time.Duration, done func(info ExitInfo, exists bool) (bool, error)) error {
	// 先立即判一次，避免起停已完成还要白等一个 tick
	if fin, err := c.pollOnce(ctx, name, done); fin || err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("systemd: waiting on unit %s: %w", name, ctx.Err())
		case <-ticker.C:
			if fin, err := c.pollOnce(ctx, name, done); fin || err != nil {
				return err
			}
		}
	}
}

func (c *Conn) pollOnce(ctx context.Context, name string, done func(ExitInfo, bool) (bool, error)) (bool, error) {
	info, exists, err := c.unitState(ctx, name)
	if err != nil {
		return false, err
	}
	return done(info, exists)
}

// unitState 读一个 unit 的 ActiveState / Result / ExecMainStatus。unit 不存在时
// exists=false（NoSuchUnit 不是错误，是一种正常状态）
func (c *Conn) unitState(ctx context.Context, name string) (ExitInfo, bool, error) {
	var unitPath dbus.ObjectPath
	call := c.mgr.CallWithContext(ctx, mgrIface+".GetUnit", 0, name)
	if call.Err != nil {
		if isNoSuchUnit(call.Err) {
			return ExitInfo{}, false, nil
		}
		return ExitInfo{}, false, fmt.Errorf("systemd: GetUnit %s: %w", name, call.Err)
	}
	if err := call.Store(&unitPath); err != nil {
		return ExitInfo{}, false, fmt.Errorf("systemd: decode unit path for %s: %w", name, err)
	}

	obj := c.bus.Object(dbusDest, unitPath)
	var info ExitInfo
	active, err := obj.GetProperty("org.freedesktop.systemd1.Unit.ActiveState")
	if err != nil {
		return ExitInfo{}, false, fmt.Errorf("systemd: get ActiveState: %w", err)
	}
	info.ActiveState, _ = active.Value().(string)
	if res, e := obj.GetProperty("org.freedesktop.systemd1.Service.Result"); e == nil {
		info.Result, _ = res.Value().(string)
	}
	if st, e := obj.GetProperty("org.freedesktop.systemd1.Service.ExecMainStatus"); e == nil {
		if v, ok := st.Value().(int32); ok {
			info.ExitStatus = int(v)
		}
	}
	return info, true, nil
}

// isNoSuchUnit 报告 D-Bus 错误是否是 systemd 的 NoSuchUnit
func isNoSuchUnit(err error) bool {
	var derr dbus.Error
	if errors.As(err, &derr) {
		return derr.Name == "org.freedesktop.systemd1.NoSuchUnit"
	}
	return false
}
