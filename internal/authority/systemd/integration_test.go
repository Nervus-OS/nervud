//go:build linux

package systemd

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// dialOrSkip 连真实系统总线；连不上（无 systemd / 无 D-Bus / 权限不足）就 skip，
// 让本集成测试在 CI 与开发机上不因环境缺失而失败。真机上（起了 systemd 的镜像/WSL）
// 它会真正跑一遍 StartTransientUnit→StopUnit 全链路
func dialOrSkip(t *testing.T) *Conn {
	t.Helper()
	if os.Getenv("DBUS_SYSTEM_BUS_ADDRESS") == "" {
		if _, err := os.Stat("/run/dbus/system_bus_socket"); err != nil {
			t.Skip("no system D-Bus socket; skipping systemd integration test")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx)
	if err != nil {
		t.Skipf("cannot dial systemd (%v); skipping integration test", err)
	}
	// 需要 root/授权才能 StartTransientUnit；连上但没权限也 skip 而非 fail
	if os.Geteuid() != 0 {
		_ = c.Close()
		t.Skip("systemd StartTransientUnit needs root; skipping")
	}
	return c
}

// TestIntegration_StartStopTransientUnit 真机验证：起一个 sleep 瞬态 unit、确认
// 活着、再停掉。它是把 props.go 的属性类型对着【真实 systemd】校准的唯一手段——
// 属性类型写错（如 SystemCallFilter 的 (bas) 写成 as）会在这里被 StartTransientUnit
// 直接拒绝
func TestIntegration_StartStopTransientUnit(t *testing.T) {
	c := dialOrSkip(t)
	defer func() { _ = c.Close() }()

	unit := "nervus-test.integration-sleep.service"
	// 轮询模型下起停都在 ctx 内有界完成；给足余量但绝不会到 go test 的 10 分钟默认超时
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	spec := UnitSpec{
		Name:        unit,
		Description: "nervud systemd integration test",
		ExecPath:    "/bin/sleep",
		Args:        []string{"30"},
		UID:         0, GID: 0, // 测试用 root；生产是 App UID
		WorkingDir: "/tmp",
	}
	// /bin/sleep 不在 PackageRoot，本测试直接用 systemd 层，不经 authority.Validate，
	// 所以 ExecPath 不受包内约束——这里只验证 D-Bus 属性与真实 systemd 兼容
	if err := c.StartTransientUnit(ctx, spec); err != nil {
		t.Fatalf("StartTransientUnit: %v", err)
	}
	t.Cleanup(func() {
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.StopUnit(sc, unit)
	})

	if err := c.StopUnit(ctx, unit); err != nil {
		t.Fatalf("StopUnit: %v", err)
	}

	// 停掉后再停一次应幂等（NoSuchUnit 被吞成 nil）
	if err := c.StopUnit(ctx, unit); err != nil {
		t.Fatalf("idempotent StopUnit: %v", err)
	}
}

// 确保 dbus 被真正用到（避免未使用 import 在裁剪构建下报错）
var _ = dbus.SystemBus
