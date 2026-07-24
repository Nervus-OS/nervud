//go:build linux

package systemd

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

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
	if os.Geteuid() != 0 {
		_ = c.Close()
		t.Skip("systemd StartTransientUnit needs root; skipping")
	}
	return c
}

func TestIntegration_StartStopTransientUnit(t *testing.T) {
	c := dialOrSkip(t)
	defer func() { _ = c.Close() }()

	unit := "nervus-test.integration-sleep.service"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	spec := UnitSpec{
		Name:        unit,
		Description: "nervud systemd integration test",
		ExecPath:    "/bin/sleep",
		Args:        []string{"30"},
		UID:         0, GID: 0,
		WorkingDir: "/tmp",
	}
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

	if err := c.StopUnit(ctx, unit); err != nil {
		t.Fatalf("idempotent StopUnit: %v", err)
	}
}

var _ = dbus.SystemBus
