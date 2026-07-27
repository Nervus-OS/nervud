//go:build !linux

package sysprobe

// MonotonicNanos is unavailable outside Linux because the production transfer
// protocol defines its deadlines in Linux CLOCK_MONOTONIC time.
func MonotonicNanos() (uint64, error) {
	return 0, ErrUnsupportedPlatform
}
