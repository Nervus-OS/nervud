//go:build linux

package sysprobe

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// MonotonicNanos returns the Linux CLOCK_MONOTONIC value in nanoseconds.
//
// The value has no wall-clock meaning. It is suitable for comparing kernel
// deadlines across processes that share the same boot, including transfer
// tickets carried over the IPC control plane.
func MonotonicNanos() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("sysprobe: clock_gettime CLOCK_MONOTONIC: %w", err)
	}
	if ts.Sec < 0 || ts.Nsec < 0 {
		return 0, fmt.Errorf("sysprobe: CLOCK_MONOTONIC returned a negative value")
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec), nil
}
