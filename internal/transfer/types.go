package transfer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

const (
	// DefaultSockPath is the production data-plane endpoint.
	DefaultSockPath = "/run/nervus/nervud-transfer.sock"

	transferIDBytes   = 16
	attachTicketBytes = 32
)

var (
	ErrUnsupportedPlatform = errors.New("transfer: data plane requires linux")
	ErrStopped             = errors.New("transfer: manager is not running")
	ErrInvalidHandle       = errors.New("transfer: response contains an invalid transfer handle")
)

// ConnID is the kernel-assigned identity of one control-plane connection.
// Equal processes on different ServiceHost connections deliberately have
// different ConnIDs.
type ConnID uint64

// PeerCredential is the immutable credential captured by the kernel when a
// Unix-domain socket connects.
type PeerCredential struct {
	PID int32
	UID uint32
	GID uint32
}

// Peer binds one route side to both its control connection and kernel
// credentials. The Package/Component fields are for revocation and audit; they
// never replace credential comparison.
type Peer struct {
	ConnID      ConnID
	PackageID   string
	ComponentID string
	Credential  PeerCredential
}

// RouteToken closes exactly once when the dispatch table removes its route.
// Begin checks it before and after insertion, closing the race with concurrent
// timeout/result/connection cleanup.
type RouteToken struct {
	closed atomic.Bool
}

// NewRouteToken creates an open token for one dispatch route.
func NewRouteToken() *RouteToken { return &RouteToken{} }

// Open reports whether the owning dispatch route still exists.
func (t *RouteToken) Open() bool { return t != nil && !t.closed.Load() }

// Close marks the route terminal and reports whether this call won the race.
func (t *RouteToken) Close() bool {
	return t != nil && t.closed.CompareAndSwap(false, true)
}

// Origin is the immutable authorization snapshot produced by IPC after it has
// proven that origin_route_id exists and targets the same ServiceHost
// connection that issued BeginTransfer.
type Origin struct {
	RouteID              uint64
	Token                *RouteToken
	Deadline             time.Time
	Caller               Peer
	Provider             Peer
	ProviderEndpointID   uint64
	BindingGeneration    uint64
	MethodID             uint32
	ResourceHandle       string
	ResourceGeneration   uint64
	RequiredPermissions  []string
	RequiresControlLease bool
	Policy               *ipcv1.TransferPolicy
}

// Clock separates policy/state-machine tests from wall time while preserving
// the protocol's CLOCK_MONOTONIC handle expiry on Linux.
type Clock interface {
	Now() time.Time
	MonotonicNanos() (uint64, error)
}

// Listener is the narrow data-listener contract needed by Manager.
type Listener interface {
	Accept() (net.Conn, error)
	Close() error
}

type ListenFunc func(path string) (Listener, error)
type PeerCredentialFunc func(net.Conn) (PeerCredential, error)

// Config contains hard kernel ceilings. MethodMeta and BeginTransfer can only
// reduce them.
type Config struct {
	SockPath       string
	Limits         Limits
	Log            *slog.Logger
	Random         io.Reader
	Clock          Clock
	Listen         ListenFunc
	PeerCredential PeerCredentialFunc
}

// StatusError is returned by Begin/Commit/Abort. IPC should expose Code and
// keep the internal message in kernel logs only.
type StatusError struct {
	Code ipcv1.StatusCode
	Err  error
}

func (e *StatusError) Error() string {
	if e == nil || e.Err == nil {
		return "transfer: request failed"
	}
	return e.Err.Error()
}

func (e *StatusError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// CodeOf maps a Manager control error to its wire status code.
func CodeOf(err error) ipcv1.StatusCode {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	if err == nil {
		return ipcv1.StatusCode_STATUS_CODE_OK
	}
	return ipcv1.StatusCode_STATUS_CODE_INTERNAL
}

func status(code ipcv1.StatusCode, text string) error {
	return &StatusError{Code: code, Err: errors.New(text)}
}

// Module is the integration surface used by the kernel lifecycle.
type Module interface {
	Name() string
	Start(context.Context) error
	Stop(context.Context) error
	Fatal() <-chan error
}
