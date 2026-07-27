//go:build linux

package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nervus-os/nervud/internal/sysprobe"
)

type platformListener struct {
	data *net.UnixListener
	lock *net.UnixListener
	once sync.Once
}

func (l *platformListener) Accept() (net.Conn, error) { return l.data.AcceptUnix() }
func (l *platformListener) Close() error {
	var errs []error
	l.once.Do(func() {
		if l.data != nil {
			errs = append(errs, l.data.Close())
		}
		if l.lock != nil {
			errs = append(errs, l.lock.Close())
		}
	})
	return errors.Join(errs...)
}

func defaultListen(path string) (Listener, error) {
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	lockName := "@nervud-transfer-" + hex.EncodeToString(sum[:12])
	lock, err := net.ListenUnix("unix", &net.UnixAddr{Name: lockName, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("acquire singleton lock: %w", err)
	}
	fail := func(err error) (Listener, error) {
		_ = lock.Close()
		return nil, err
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&fs.ModeSocket == 0 {
			return fail(fmt.Errorf("%s exists and is not a socket", path))
		}
		if err := os.Remove(path); err != nil {
			return fail(fmt.Errorf("remove stale socket: %w", err))
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return fail(fmt.Errorf("stat socket: %w", statErr))
	}
	data, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	data.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o666); err != nil {
		_ = data.Close()
		return fail(fmt.Errorf("chmod socket: %w", err))
	}
	return &platformListener{data: data, lock: lock}, nil
}

func defaultPeerCredential(conn net.Conn) (PeerCredential, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerCredential{}, errors.New("transfer: peer is not a Unix connection")
	}
	cred, err := sysprobe.PeerCred(uc)
	if err != nil {
		return PeerCredential{}, err
	}
	return PeerCredential{PID: cred.PID, UID: cred.UID, GID: cred.GID}, nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
func (systemClock) MonotonicNanos() (uint64, error) {
	return sysprobe.MonotonicNanos()
}
