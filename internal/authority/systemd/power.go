// 本文件是整机电源动作: 经 systemd 的 D-Bus 接口发起有序重启/关机.
//
// # 为什么不用 reboot(2)
//
// ops.go 的 osReboot 走 unix.Reboot(LINUX_REBOOT_CMD_RESTART) - sync 之后立即
// 生效, 不给任何上层留 flush 机会. 那是故障恢复路径: 内核已经判定系统不可信,
// 越快离开当前状态越好, 代价是所有正在运行的组件被硬断.
//
// 用户在设置里点"重启"是另一件事: 机器此刻是健康的, 正在跑的组件应当收到
// SIGTERM, 有机会落盘, 文件系统应当被正常卸载. 这条路由 systemd 走完整的
// shutdown.target, 与在终端敲 systemctl reboot 完全等价.
//
// 两条路都保留, 都不能删: 一个是"机器坏了赶紧重来", 一个是"用户要关机".
package systemd

import (
	"context"
	"fmt"
)

// Reboot 请求 systemd 有序重启整机.
//
// 这个调用正常情况下不返回: systemd 收到后立即开始停机流程, D-Bus 连接
// 会随之断开. 因此调用方不应把"返回了 error"当成"没有重启" - 连接被断开
// 产生的 error 恰恰是重启已经开始的证据. 见 authority.Gate.osPower 的处理.
func (c *Conn) Reboot(ctx context.Context) error {
	if call := c.mgr.CallWithContext(ctx, mgrIface+".Reboot", 0); call.Err != nil {
		return fmt.Errorf("systemd: Reboot: %w", call.Err)
	}
	return nil
}

// PowerOff 请求 systemd 有序关机. 返回语义同 Reboot.
func (c *Conn) PowerOff(ctx context.Context) error {
	if call := c.mgr.CallWithContext(ctx, mgrIface+".PowerOff", 0); call.Err != nil {
		return fmt.Errorf("systemd: PowerOff: %w", call.Err)
	}
	return nil
}
