//go:build !linux

package transfer

import (
	"net"
	"time"
)

func defaultListen(string) (Listener, error) {
	return nil, ErrUnsupportedPlatform
}

func defaultPeerCredential(net.Conn) (PeerCredential, error) {
	return PeerCredential{}, ErrUnsupportedPlatform
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
func (systemClock) MonotonicNanos() (uint64, error) {
	return 0, ErrUnsupportedPlatform
}
