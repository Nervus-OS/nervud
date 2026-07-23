package safety

import (
	"testing"
	"time"
)

func TestDefaultContract_Valid(t *testing.T) {
	if err := DefaultContract().Validate(); err != nil {
		t.Fatalf("DefaultContract must be valid: %v", err)
	}
}

func TestContract_Validate(t *testing.T) {
	base := DefaultContract()

	tests := []struct {
		name    string
		mutate  func(*Contract)
		wantErr bool
	}{
		{"ok", func(*Contract) {}, false},
		{"zero halt budget", func(c *Contract) { c.HaltDispatchBudget = 0 }, true},
		{"negative accept", func(c *Contract) { c.ProviderAcceptTimeout = -1 }, true},
		{"zero standstill", func(c *Contract) { c.StandstillTimeout = 0 }, true},
		{"zero mcu watchdog", func(c *Contract) { c.MCUWatchdogTimeout = 0 }, true},
		{"accept exceeds deviceAck", func(c *Contract) {
			c.ProviderAcceptTimeout = 500 * time.Millisecond
			c.DeviceStopAckTimeout = 100 * time.Millisecond
		}, true},
		{"deviceAck exceeds standstill", func(c *Contract) {
			c.DeviceStopAckTimeout = 2 * time.Second
			c.StandstillTimeout = 1 * time.Second
		}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
