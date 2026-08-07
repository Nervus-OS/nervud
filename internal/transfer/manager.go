package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	transferv1 "github.com/nervus-os/nervus-ipc/protocol/interface/transferv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

// Manager owns all Transfer state and the data-plane listener.
type Manager struct {
	sockPath string
	limits   Limits
	log      *slog.Logger
	random   io.Reader
	clock    Clock
	listen   ListenFunc
	peerCred PeerCredentialFunc

	mu              sync.Mutex
	started         bool
	stopping        bool
	ln              Listener
	records         map[transferID]*record
	byRoute         map[uint64]map[transferID]struct{}
	perUIDCount     map[uint32]int
	perUIDBPS       map[uint32]uint64
	liveCount       int
	tombstones      int
	reservedBPS     uint64
	reservedBuffers uint64
	pending         int
	pendingUID      map[uint32]int
	pendingConns    map[net.Conn]struct{}

	quit      chan struct{}
	quitOnce  sync.Once
	wg        sync.WaitGroup
	fatal     chan error
	fatalOnce sync.Once
}

// New constructs a stopped Manager. Start owns the listener lifecycle.
func New(cfg Config) (*Manager, error) {
	path := cfg.SockPath
	if path == "" {
		path = DefaultSockPath
	}
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("transfer: socket path %q must be absolute", path)
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	clock := cfg.Clock
	if clock == nil {
		clock = systemClock{}
	}
	listen := cfg.Listen
	if listen == nil {
		listen = defaultListen
	}
	peerCred := cfg.PeerCredential
	if peerCred == nil {
		peerCred = defaultPeerCredential
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	return &Manager{
		sockPath:     path,
		limits:       normalizeLimits(cfg.Limits),
		log:          log,
		random:       random,
		clock:        clock,
		listen:       listen,
		peerCred:     peerCred,
		records:      make(map[transferID]*record),
		byRoute:      make(map[uint64]map[transferID]struct{}),
		perUIDCount:  make(map[uint32]int),
		perUIDBPS:    make(map[uint32]uint64),
		pendingUID:   make(map[uint32]int),
		pendingConns: make(map[net.Conn]struct{}),
		quit:         make(chan struct{}),
		fatal:        make(chan error, 1),
	}, nil
}

// Name implements kernel.Module.
func (m *Manager) Name() string { return "transfer" }

// Fatal reports an unrecoverable listener failure to the kernel.
func (m *Manager) Fatal() <-chan error { return m.fatal }

// SockPath returns the data-plane endpoint embedded in issued handles.
func (m *Manager) SockPath() string { return m.sockPath }

// Start binds the data-plane endpoint and starts accept/reaper goroutines.
func (m *Manager) Start(context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("transfer: already started")
	}
	if m.stopping {
		m.mu.Unlock()
		return ErrStopped
	}
	m.started = true
	m.mu.Unlock()

	if _, err := m.clock.MonotonicNanos(); err != nil {
		m.mu.Lock()
		m.started = false
		m.mu.Unlock()
		return fmt.Errorf("transfer: monotonic clock unavailable: %w", err)
	}
	ln, err := m.listen(m.sockPath)
	if err != nil {
		m.mu.Lock()
		m.started = false
		m.mu.Unlock()
		return fmt.Errorf("transfer: listen %s: %w", m.sockPath, err)
	}
	m.mu.Lock()
	if m.stopping {
		m.mu.Unlock()
		_ = ln.Close()
		return ErrStopped
	}
	m.ln = ln
	m.mu.Unlock()

	m.wg.Add(2)
	go m.acceptLoop()
	go m.reapLoop()
	m.log.Info("transfer: listening", "sock", m.sockPath)
	return nil
}

// Begin creates one PREPARED transfer. IPC must construct Origin only after
// matching origin_route_id to the current provider control connection.
func (m *Manager) Begin(origin Origin, req *transferv1.BeginTransferRequest) (*transferv1.BeginTransferResponse, error) {
	now := m.clock.Now()
	if req == nil || req.GetOriginRouteId() != origin.RouteID ||
		origin.RouteID == 0 || !origin.Token.Open() ||
		origin.Deadline.IsZero() || !now.Before(origin.Deadline) {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: origin route is not live")
	}
	if origin.Caller.ConnID == 0 || origin.Provider.ConnID == 0 ||
		origin.Policy == nil {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: incomplete origin authorization")
	}
	if (origin.ResourceHandle == "") != (origin.ResourceGeneration == 0) {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: resource handle and generation are inconsistent")
	}
	policy := origin.Policy
	direction := req.GetDirection()
	if !directionAllowed(policy.GetDirection(), direction) {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			"transfer: requested direction exceeds method policy")
	}
	// 至少要允许一种本 build 实现的模式。FRAMED_RELAY 是基线，
	// SHARED_MEMORY_RING 需要方法显式允许
	ringAllowed := modeAllowed(policy.GetAllowedModes(),
		ipcv1.TransferMode_TRANSFER_MODE_SHARED_MEMORY_RING)
	if !framedRelayAllowed(policy.GetAllowedModes()) && !ringAllowed {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: method allows no implemented transfer mode")
	}
	switch req.GetPreferredMode() {
	case ipcv1.TransferMode_TRANSFER_MODE_UNSPECIFIED,
		ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY,
		ipcv1.TransferMode_TRANSFER_MODE_SHARED_MEMORY_RING:
	default:
		return nil, status(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			"transfer: unknown preferred mode")
	}
	if policy.GetMaxStreams() == 0 || policy.GetMaxPacketBytes() == 0 ||
		policy.GetMaxBytesPerSecond() == 0 {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: method transfer policy is unbounded")
	}

	maxPacket := minU32(policy.GetMaxPacketBytes(), m.limits.MaxPacketBytes)
	if requested := req.GetRequestedMaxPacketBytes(); requested != 0 {
		maxPacket = minU32(maxPacket, requested)
	}
	maxBPS := minU64(policy.GetMaxBytesPerSecond(), m.limits.MaxBytesPerSecond)
	if requested := req.GetRequestedBytesPerSecond(); requested != 0 {
		maxBPS = minU64(maxBPS, requested)
	}
	if maxPacket == 0 || maxBPS == 0 {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			"transfer: effective limits must be non-zero")
	}
	directions := relayDirections(direction)
	if uint64(maxPacket) > ^uint64(0)/directions {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
			"transfer: relay buffer reservation overflows")
	}
	bufferReservation := uint64(maxPacket) * directions

	monoNow, err := m.clock.MonotonicNanos()
	if err != nil {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
			"transfer: monotonic clock unavailable")
	}
	providerExpires := minTime(now.Add(m.limits.ProviderAttachTimeout), origin.Deadline)
	callerExpires := minTime(origin.Deadline.Add(m.limits.CallerAttachGrace),
		now.Add(m.limits.MaxHandleLifetime))
	if !providerExpires.After(now) || !callerExpires.After(now) {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED,
			"transfer: route has no attachment budget")
	}
	providerMono, ok := addMonotonic(monoNow, providerExpires.Sub(now))
	if !ok {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			"transfer: provider expiry overflow")
	}
	callerMono, ok := addMonotonic(monoNow, callerExpires.Sub(now))
	if !ok {
		return nil, status(ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			"transfer: caller expiry overflow")
	}

	idWire, err := randomBytes(m.random, transferIDBytes)
	if err != nil {
		return nil, err
	}
	providerTicket, err := randomBytes(m.random, attachTicketBytes)
	if err != nil {
		return nil, err
	}
	callerTicket, err := randomBytes(m.random, attachTicketBytes)
	if err != nil {
		return nil, err
	}
	id, _ := parseTransferID(idWire)
	providerRole, callerRole, _ := rolesFor(direction)

	// 模式裁决：只有「方法允许 + 调用方请求 + 本机支持」三者同时成立才用 ring。
	//
	// 任何一项不成立都静默回落到 FRAMED_RELAY 而不是报错——ring 是性能优化，
	// 不是语义变更，因为一台内核太老的开发机而让整条链路失败不划算。
	mode := ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY
	var ring *ringResources
	if ringAllowed &&
		req.GetPreferredMode() == ipcv1.TransferMode_TRANSFER_MODE_SHARED_MEMORY_RING &&
		ringModeSupported() {
		res, ringErr := newRingResources(maxPacket)
		if ringErr != nil {
			// 建不出来同样回落。日志留在 Manager 侧，调用方只看到模式不同
			if m.log != nil {
				m.log.Warn("transfer: shared-memory ring unavailable, falling back to framed relay",
					"err", ringErr)
			}
		} else {
			mode = ipcv1.TransferMode_TRANSFER_MODE_SHARED_MEMORY_RING
			ring = res
		}
	}

	r := &record{
		id: id, routeID: origin.RouteID, token: origin.Token,
		deadline: origin.Deadline, endpointID: origin.ProviderEndpointID,
		generation: origin.BindingGeneration,
		resource:   origin.ResourceHandle, resourceGen: origin.ResourceGeneration,
		permissions:   append([]string(nil), origin.RequiredPermissions...),
		requiresLease: origin.RequiresControlLease,
		direction:     direction,
		mode:          mode,
		ring:          ring,
		maxPacket:     maxPacket, maxBPS: maxBPS,
		bufferReservation: bufferReservation,
		provider: transferSide{
			owner: origin.Provider, role: providerRole,
			ticketDigest: ticketDigest(providerTicket),
			expiresAt:    providerExpires, expiresMono: providerMono,
		},
		caller: transferSide{
			owner: origin.Caller, role: callerRole,
			ticketDigest: ticketDigest(callerTicket),
			expiresAt:    callerExpires, expiresMono: callerMono,
		},
		state: statePrepared, budgeted: true, bufferBudgeted: true,
		done:  make(chan struct{}),
		pacer: newPacer(maxBPS, m.limits.MaxFramesPerSecond),
	}

	m.mu.Lock()
	if !m.started || m.stopping || !origin.Token.Open() {
		m.mu.Unlock()
		return nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: origin closed while preparing transfer")
	}
	if _, collision := m.records[id]; collision {
		m.mu.Unlock()
		return nil, status(ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			"transfer: random transfer id collision")
	}
	routeSet := m.byRoute[origin.RouteID]
	if len(routeSet) >= int(policy.GetMaxStreams()) {
		m.mu.Unlock()
		return nil, status(ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
			"transfer: method max_streams exhausted")
	}
	if err := m.reserveLocked(r); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if routeSet == nil {
		routeSet = make(map[transferID]struct{})
		m.byRoute[origin.RouteID] = routeSet
	}
	m.records[id] = r
	routeSet[id] = struct{}{}
	if !origin.Token.Open() {
		conns := m.closeLocked(r, terminalRouteFailed, now)
		m.mu.Unlock()
		closeConns(conns)
		return nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: origin closed while preparing transfer")
	}
	m.mu.Unlock()

	return &transferv1.BeginTransferResponse{
		Provider: makeHandle(id, providerTicket, r.provider, r.mode, m.sockPath),
		Caller:   makeHandle(id, callerTicket, r.caller, r.mode, m.sockPath),
	}, nil
}

// Commit makes the caller ticket attachable after the provider side attached.
func (m *Manager) Commit(provider ConnID, transferIDWire []byte) error {
	id, ok := parseTransferID(transferIDWire)
	if !ok {
		return status(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			"transfer: transfer id must be 16 bytes")
	}
	now := m.clock.Now()
	m.mu.Lock()
	r := m.records[id]
	if r == nil || r.provider.owner.ConnID != provider {
		m.mu.Unlock()
		return status(ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, "transfer: transfer not found")
	}
	switch r.state {
	case stateCommitted, stateActive:
		m.mu.Unlock()
		return nil
	case stateClosed:
		committed := r.everCommitted
		m.mu.Unlock()
		if committed {
			return nil
		}
		return status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: transfer is closed")
	case statePrepared:
	default:
		m.mu.Unlock()
		return status(ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			"transfer: invalid lifecycle state")
	}
	if !r.token.Open() || !now.Before(r.deadline) || !now.Before(r.caller.expiresAt) {
		conns := m.closeLocked(r, terminalExpired, now)
		m.mu.Unlock()
		closeConns(conns)
		return status(ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED,
			"transfer: transfer expired before commit")
	}
	if r.provider.conn == nil || !r.provider.consumed {
		m.mu.Unlock()
		return status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: provider must attach before commit")
	}
	r.state = stateCommitted
	r.everCommitted = true
	m.mu.Unlock()
	return nil
}

// Abort closes a transfer owned by provider. Repeating the same Abort is
// idempotent while its bounded terminal record is retained.
func (m *Manager) Abort(provider ConnID, transferIDWire []byte) error {
	id, ok := parseTransferID(transferIDWire)
	if !ok {
		return status(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			"transfer: transfer id must be 16 bytes")
	}
	now := m.clock.Now()
	m.mu.Lock()
	r := m.records[id]
	if r == nil || r.provider.owner.ConnID != provider {
		m.mu.Unlock()
		return status(ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, "transfer: transfer not found")
	}
	if r.state == stateClosed {
		same := r.terminal == terminalExplicitAbort
		m.mu.Unlock()
		if same {
			return nil
		}
		return status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: transfer already closed")
	}
	conns := m.closeLocked(r, terminalExplicitAbort, now)
	m.mu.Unlock()
	closeConns(conns)
	return nil
}

// FinishRoute atomically validates all caller handles in a successful response.
// Only exact, committed handles created by this route survive.
func (m *Manager) FinishRoute(routeID uint64, success bool, referenced []*ipcv1.TransferHandle) error {
	now := m.clock.Now()
	m.mu.Lock()
	ids := m.byRoute[routeID]
	if !success {
		conns := m.closeSetLocked(ids, terminalRouteFailed, now)
		m.mu.Unlock()
		closeConns(conns)
		return nil
	}

	keep := make(map[transferID]struct{}, len(referenced))
	valid := true
	for _, h := range referenced {
		id, ok := parseTransferID(h.GetTransferId())
		if !ok {
			valid = false
			break
		}
		if _, duplicate := keep[id]; duplicate {
			valid = false
			break
		}
		r := m.records[id]
		if _, belongs := ids[id]; !belongs || r == nil ||
			(r.state != stateCommitted && r.state != stateActive) ||
			!handleMatches(r, &r.caller, h, m.sockPath) {
			valid = false
			break
		}
		keep[id] = struct{}{}
	}
	if !valid {
		conns := m.closeSetLocked(ids, terminalProtocol, now)
		m.mu.Unlock()
		closeConns(conns)
		return ErrInvalidHandle
	}
	var conns []net.Conn
	for id := range ids {
		r := m.records[id]
		if r == nil || r.state == stateClosed {
			continue
		}
		if _, ok := keep[id]; ok {
			r.originFinished = true
			r.retained = true
			continue
		}
		conns = append(conns, m.closeLocked(r, terminalUnreferenced, now)...)
	}
	m.mu.Unlock()
	closeConns(conns)
	return nil
}

// CloseRoute terminates everything created by a failed or undeliverable route.
func (m *Manager) CloseRoute(routeID uint64) {
	now := m.clock.Now()
	m.mu.Lock()
	conns := m.closeSetLocked(m.byRoute[routeID], terminalRouteFailed, now)
	m.mu.Unlock()
	closeConns(conns)
}

// ConnClosed terminates transfers owned by either side of a control connection.
func (m *Manager) ConnClosed(conn ConnID) {
	now := m.clock.Now()
	m.mu.Lock()
	var conns []net.Conn
	for _, r := range m.records {
		if r.state != stateClosed &&
			(r.provider.owner.ConnID == conn || r.caller.owner.ConnID == conn) {
			conns = append(conns, m.closeLocked(r, terminalPeerClosed, now)...)
		}
	}
	m.mu.Unlock()
	closeConns(conns)
}

// EndpointRevoked closes streams created by one provider registration.
// A zero generation matches every generation of that endpoint ID.
func (m *Manager) EndpointRevoked(provider ConnID, endpointID, generation uint64) {
	now := m.clock.Now()
	m.mu.Lock()
	var conns []net.Conn
	for _, r := range m.records {
		if r.state != stateClosed && r.provider.owner.ConnID == provider &&
			r.endpointID == endpointID && (generation == 0 || r.generation == generation) {
			conns = append(conns, m.closeLocked(r, terminalRevoked, now)...)
		}
	}
	m.mu.Unlock()
	closeConns(conns)
}

// RevokePackage closes all transfers involving packageID.
func (m *Manager) RevokePackage(packageID string) {
	now := m.clock.Now()
	m.mu.Lock()
	var conns []net.Conn
	for _, r := range m.records {
		if r.state != stateClosed &&
			(r.provider.owner.PackageID == packageID || r.caller.owner.PackageID == packageID) {
			conns = append(conns, m.closeLocked(r, terminalRevoked, now)...)
		}
	}
	m.mu.Unlock()
	closeConns(conns)
}

// RevokePermission closes caller transfers authorized by permission.
func (m *Manager) RevokePermission(packageID, permission string) {
	now := m.clock.Now()
	m.mu.Lock()
	var conns []net.Conn
	for _, r := range m.records {
		if r.state != stateClosed && r.caller.owner.PackageID == packageID &&
			containsString(r.permissions, permission) {
			conns = append(conns, m.closeLocked(r, terminalRevoked, now)...)
		}
	}
	m.mu.Unlock()
	closeConns(conns)
}

// RevokeResource closes transfers authorized by one obsolete catalog resource
// generation. A replacement using the same stable handle remains valid.
func (m *Manager) RevokeResource(resource string, generation uint64) {
	now := m.clock.Now()
	m.mu.Lock()
	var conns []net.Conn
	for _, r := range m.records {
		if r.state != stateClosed && r.resource == resource &&
			r.resourceGen == generation {
			conns = append(conns, m.closeLocked(r, terminalRevoked, now)...)
		}
	}
	m.mu.Unlock()
	closeConns(conns)
}

// RevokeControl closes streams whose originating method required a control
// lease on this caller connection and resource.
func (m *Manager) RevokeControl(caller ConnID, resource string) {
	now := m.clock.Now()
	m.mu.Lock()
	var conns []net.Conn
	for _, r := range m.records {
		if r.state != stateClosed && r.requiresLease &&
			r.caller.owner.ConnID == caller && r.resource == resource {
			conns = append(conns, m.closeLocked(r, terminalRevoked, now)...)
		}
	}
	m.mu.Unlock()
	closeConns(conns)
}

// Stop stops admission, closes pending and active sockets, and joins workers.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	if m.stopping {
		m.mu.Unlock()
		return nil
	}
	m.stopping = true
	ln := m.ln
	m.mu.Unlock()
	m.quitOnce.Do(func() { close(m.quit) })
	var stopErrs []error
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			stopErrs = append(stopErrs, fmt.Errorf("transfer: close listener: %w", err))
		}
	}

	now := m.clock.Now()
	m.mu.Lock()
	var conns []net.Conn
	for conn := range m.pendingConns {
		conns = append(conns, conn)
	}
	for _, r := range m.records {
		if r.state != stateClosed {
			conns = append(conns, m.closeLocked(r, terminalStopped, now)...)
		}
	}
	m.mu.Unlock()
	closeConns(conns)

	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
		return errors.Join(stopErrs...)
	case <-ctx.Done():
		stopErrs = append(stopErrs,
			fmt.Errorf("transfer: goroutines not drained: %w", ctx.Err()))
		return errors.Join(stopErrs...)
	}
}

func (m *Manager) reserveLocked(r *record) error {
	if m.liveCount >= m.limits.MaxTransfers {
		return status(ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
			"transfer: global transfer limit reached")
	}
	if m.tombstones >= m.limits.MaxTombstones {
		return status(ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
			"transfer: terminal-state retention limit reached")
	}
	if r.maxBPS > m.limits.MaxReservedBytesPerSecond ||
		m.reservedBPS > m.limits.MaxReservedBytesPerSecond-r.maxBPS {
		return status(ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
			"transfer: global bandwidth budget exhausted")
	}
	if r.bufferReservation > m.limits.MaxRelayBufferBytes ||
		m.reservedBuffers > m.limits.MaxRelayBufferBytes-r.bufferReservation {
		return status(ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
			"transfer: relay buffer budget exhausted")
	}
	for _, uid := range r.peerUIDs() {
		if m.perUIDCount[uid] >= m.limits.MaxTransfersPerUID {
			return status(ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
				"transfer: per-uid transfer limit reached")
		}
		if r.maxBPS > m.limits.MaxReservedBytesPerSecondPerUID ||
			m.perUIDBPS[uid] > m.limits.MaxReservedBytesPerSecondPerUID-r.maxBPS {
			return status(ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
				"transfer: per-uid bandwidth budget exhausted")
		}
	}
	m.liveCount++
	m.reservedBPS += r.maxBPS
	m.reservedBuffers += r.bufferReservation
	for _, uid := range r.peerUIDs() {
		m.perUIDCount[uid]++
		m.perUIDBPS[uid] += r.maxBPS
	}
	return nil
}

func (m *Manager) releaseLocked(r *record) {
	if !r.budgeted {
		return
	}
	r.budgeted = false
	m.liveCount--
	m.reservedBPS -= r.maxBPS
	if r.relayWorkers == 0 {
		m.releaseBufferLocked(r)
	}
	for _, uid := range r.peerUIDs() {
		if m.perUIDCount[uid] <= 1 {
			delete(m.perUIDCount, uid)
		} else {
			m.perUIDCount[uid]--
		}
		if m.perUIDBPS[uid] <= r.maxBPS {
			delete(m.perUIDBPS, uid)
		} else {
			m.perUIDBPS[uid] -= r.maxBPS
		}
	}
}

func (m *Manager) releaseBufferLocked(r *record) {
	if !r.bufferBudgeted {
		return
	}
	r.bufferBudgeted = false
	m.reservedBuffers -= r.bufferReservation
}

func (m *Manager) closeLocked(r *record, reason terminalReason, now time.Time) []net.Conn {
	if r == nil || r.state == stateClosed {
		return nil
	}
	r.state = stateClosed
	m.tombstones++
	r.terminal = reason
	r.terminalAt = now
	r.closeSignal()
	m.releaseLocked(r)
	// 释放 ring 的 memfd 与 eventfd。
	//
	// nervud 关掉自己这两个 fd 之后，内存本身由两端已经收到的 fd 引用计数维持，
	// 直到它们各自退出或关闭——这正是想要的：传输结束时内核不再持有引用，
	// 而对端在处理完最后一帧之前不会被抽掉内存
	if r.ring != nil {
		r.ring.close()
		r.ring = nil
	}
	var conns []net.Conn
	if r.provider.conn != nil {
		conns = append(conns, r.provider.conn)
		r.provider.conn = nil
	}
	if r.caller.conn != nil {
		conns = append(conns, r.caller.conn)
		r.caller.conn = nil
	}
	return conns
}

func (m *Manager) closeSetLocked(ids map[transferID]struct{}, reason terminalReason, now time.Time) []net.Conn {
	var conns []net.Conn
	for id := range ids {
		conns = append(conns, m.closeLocked(m.records[id], reason, now)...)
	}
	return conns
}

func closeConns(conns []net.Conn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

func makeHandle(id transferID, ticket []byte, side transferSide, mode ipcv1.TransferMode, endpoint string) *ipcv1.TransferHandle {
	return &ipcv1.TransferHandle{
		TransferId:              append([]byte(nil), id[:]...),
		AttachTicket:            append([]byte(nil), ticket...),
		Role:                    side.role,
		Mode:                    mode,
		ExpiresAtMonotonicNanos: side.expiresMono,
		DataPlaneEndpoint:       endpoint,
	}
}

func handleMatches(r *record, side *transferSide, h *ipcv1.TransferHandle, endpoint string) bool {
	if r == nil || side == nil || h == nil {
		return false
	}
	return bytes.Equal(h.GetTransferId(), r.id[:]) &&
		ticketMatches(side.ticketDigest, h.GetAttachTicket()) &&
		h.GetRole() == side.role &&
		h.GetMode() == r.mode &&
		h.GetExpiresAtMonotonicNanos() == side.expiresMono &&
		h.GetDataPlaneEndpoint() == endpoint
}

// framedRelayAllowed：空集合表示只允许基线模式（见 TransferPolicy.allowed_modes
// 的注释），因此空集合恒为 true。
func framedRelayAllowed(modes []ipcv1.TransferMode) bool {
	if len(modes) == 0 {
		return true
	}
	return modeAllowed(modes, ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY)
}

// modeAllowed 判断某个模式是否在方法声明的白名单里。
//
// 【空集合不代表允许任意模式】：它按 TransferPolicy 的定义等价于「只允许
// FRAMED_RELAY」。因此 ring 必须被显式列出才可用——一个没想过共享内存的方法
// 不该因为调用方请求就获得它。
func modeAllowed(modes []ipcv1.TransferMode, want ipcv1.TransferMode) bool {
	for _, mode := range modes {
		if mode == want {
			return true
		}
	}
	return false
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func addMonotonic(base uint64, d time.Duration) (uint64, bool) {
	if d <= 0 {
		return 0, false
	}
	n := uint64(d)
	if base > ^uint64(0)-n {
		return 0, false
	}
	return base + n, true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
