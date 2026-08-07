package transfer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	transferv1 "github.com/nervus-os/nervus-ipc/protocol/interface/transferv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"
)

type fakeClock struct {
	mu   sync.Mutex
	now  time.Time
	mono uint64
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) MonotonicNanos() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono, nil
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mono += uint64(d)
	c.mu.Unlock()
}

type fakeListener struct {
	accept chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{accept: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func newTestManager(t *testing.T, mutate func(*Config)) (*Manager, *fakeClock) {
	t.Helper()
	clock := &fakeClock{
		now:  time.Now(),
		mono: uint64(10 * time.Second),
	}
	listener := newFakeListener()
	cfg := Config{
		SockPath: "/tmp/nervud-transfer-test.sock",
		Clock:    clock,
		Listen: func(string) (Listener, error) {
			return listener, nil
		},
		PeerCredential: func(net.Conn) (PeerCredential, error) {
			return PeerCredential{}, errors.New("test must inject credentials directly")
		},
		Limits: Limits{
			ReapInterval: time.Hour,
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.Stop(ctx); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	return m, clock
}

func testOrigin(clock *fakeClock, direction ipcv1.TransferDirection) Origin {
	return Origin{
		RouteID:  77,
		Token:    NewRouteToken(),
		Deadline: clock.Now().Add(20 * time.Second),
		Caller: Peer{
			ConnID: 11, PackageID: "com.example.caller", ComponentID: "main",
			Credential: PeerCredential{PID: 101, UID: 21001, GID: 21001},
		},
		Provider: Peer{
			ConnID: 22, PackageID: "com.example.provider", ComponentID: "camera",
			Credential: PeerCredential{PID: 202, UID: 21002, GID: 21002},
		},
		ProviderEndpointID:  3,
		BindingGeneration:   9,
		MethodID:            1,
		ResourceHandle:      "camera.main",
		ResourceGeneration:  1,
		RequiredPermissions: []string{"perm.camera.capture"},
		Policy: &ipcv1.TransferPolicy{
			Direction: direction, MaxStreams: 1,
			MaxPacketBytes: 1024, MaxBytesPerSecond: 1 << 20,
			AllowedModes: []ipcv1.TransferMode{
				ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY,
			},
		},
	}
}

func beginTestTransfer(t *testing.T, m *Manager, origin Origin) *transferv1.BeginTransferResponse {
	t.Helper()
	resp, err := m.Begin(origin, &transferv1.BeginTransferRequest{
		OriginRouteId: origin.RouteID,
		Direction:     origin.Policy.GetDirection(),
		PreferredMode: ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY,
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return resp
}

func attachDirect(
	t *testing.T, m *Manager, handle *ipcv1.TransferHandle, cred PeerCredential,
) (net.Conn, transferID, bool, error) {
	t.Helper()
	server, client := net.Pipe()
	req := &ipcv1.AttachTransfer{
		TransferId: handle.GetTransferId(), AttachTicket: handle.GetAttachTicket(),
		Role: handle.GetRole(),
	}
	_, id, active, _, err := m.attach(server, cred, req)
	if err != nil {
		_ = server.Close()
		_ = client.Close()
		return nil, id, active, err
	}
	return client, id, active, nil
}

func TestBeginCommitAttachAndFinishRoute(t *testing.T) {
	m, clock := newTestManager(t, nil)
	origin := testOrigin(clock, ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
	resp := beginTestTransfer(t, m, origin)
	if err := m.Commit(999, resp.GetProvider().GetTransferId()); CodeOf(err) !=
		ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("cross-connection Commit = %v, code %s", err, CodeOf(err))
	}

	if err := m.Commit(origin.Provider.ConnID, resp.GetProvider().GetTransferId()); CodeOf(err) !=
		ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("Commit before provider attach = %v, code %s", err, CodeOf(err))
	}

	// A stolen provider ticket from a different PID must fail without burning it.
	if _, _, _, err := attachDirect(t, m, resp.GetProvider(),
		PeerCredential{PID: 999, UID: origin.Provider.Credential.UID, GID: origin.Provider.Credential.GID}); err == nil {
		t.Fatal("wrong PID was allowed to attach")
	}
	providerClient, _, active, err := attachDirect(t, m, resp.GetProvider(), origin.Provider.Credential)
	if err != nil || active {
		t.Fatalf("provider attach = active:%v err:%v", active, err)
	}
	defer providerClient.Close()

	// Caller racing before Commit is rejected, but the same one-time ticket is
	// still valid after Commit.
	if _, _, _, err := attachDirect(t, m, resp.GetCaller(), origin.Caller.Credential); CodeOf(err) != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("caller pre-commit attach = %v, code %s", err, CodeOf(err))
	}
	if err := m.Commit(origin.Provider.ConnID, resp.GetProvider().GetTransferId()); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := m.Commit(origin.Provider.ConnID, resp.GetProvider().GetTransferId()); err != nil {
		t.Fatalf("duplicate Commit: %v", err)
	}
	callerClient, _, active, err := attachDirect(t, m, resp.GetCaller(), origin.Caller.Credential)
	if err != nil || !active {
		t.Fatalf("caller attach = active:%v err:%v", active, err)
	}
	defer callerClient.Close()

	// A consumed ticket cannot be replayed.
	if _, _, _, err := attachDirect(t, m, resp.GetCaller(), origin.Caller.Credential); err == nil {
		t.Fatal("caller ticket replay was accepted")
	}
	if err := m.FinishRoute(origin.RouteID, true,
		[]*ipcv1.TransferHandle{proto.Clone(resp.GetCaller()).(*ipcv1.TransferHandle)}); err != nil {
		t.Fatalf("FinishRoute: %v", err)
	}

	m.ConnClosed(origin.Caller.ConnID)
	id, _ := parseTransferID(resp.GetCaller().GetTransferId())
	m.mu.Lock()
	state := m.records[id].state
	m.mu.Unlock()
	if state != stateClosed {
		t.Fatalf("state after caller control disconnect = %v", state)
	}
}

func TestRevokeResourceMatchesDefinitionGeneration(t *testing.T) {
	m, clock := newTestManager(t, nil)
	origin := testOrigin(
		clock, ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
	origin.ResourceGeneration = 9
	response := beginTestTransfer(t, m, origin)
	id, ok := parseTransferID(response.GetProvider().GetTransferId())
	if !ok {
		t.Fatal("Begin returned an invalid transfer ID")
	}

	m.RevokeResource(origin.ResourceHandle, 8)
	m.mu.Lock()
	stateAfterOld := m.records[id].state
	m.mu.Unlock()
	if stateAfterOld == stateClosed {
		t.Fatal("old resource generation revoked a replacement transfer")
	}

	m.RevokeResource(origin.ResourceHandle, origin.ResourceGeneration)
	m.mu.Lock()
	stateAfterMatch := m.records[id].state
	m.mu.Unlock()
	if stateAfterMatch != stateClosed {
		t.Fatalf("matching resource generation left state %v", stateAfterMatch)
	}
}

func TestFinishRouteRejectsForgedHandleAndClosesTransfer(t *testing.T) {
	m, clock := newTestManager(t, nil)
	origin := testOrigin(clock, ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
	resp := beginTestTransfer(t, m, origin)
	providerClient, _, _, err := attachDirect(t, m, resp.GetProvider(), origin.Provider.Credential)
	if err != nil {
		t.Fatalf("provider attach: %v", err)
	}
	defer providerClient.Close()
	if err := m.Commit(origin.Provider.ConnID, resp.GetProvider().GetTransferId()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	forged := proto.Clone(resp.GetCaller()).(*ipcv1.TransferHandle)
	forged.DataPlaneEndpoint = "/tmp/attacker.sock"
	if err := m.FinishRoute(origin.RouteID, true, []*ipcv1.TransferHandle{forged}); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("FinishRoute forged handle = %v", err)
	}
	id, _ := parseTransferID(resp.GetCaller().GetTransferId())
	m.mu.Lock()
	state := m.records[id].state
	m.mu.Unlock()
	if state != stateClosed {
		t.Fatalf("forged response left state %v", state)
	}
}

type closingReader struct {
	token *RouteToken
	once  sync.Once
}

func (r *closingReader) Read(p []byte) (int, error) {
	r.once.Do(func() { r.token.Close() })
	for i := range p {
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

func TestBeginClosesRouteRaceWithoutLeakingBudget(t *testing.T) {
	token := NewRouteToken()
	var reader *closingReader
	m, clock := newTestManager(t, func(cfg *Config) {
		reader = &closingReader{token: token}
		cfg.Random = reader
	})
	origin := testOrigin(clock, ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
	origin.Token = token
	_, err := m.Begin(origin, &transferv1.BeginTransferRequest{
		OriginRouteId: origin.RouteID, Direction: origin.Policy.GetDirection(),
	})
	if CodeOf(err) != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("Begin after concurrent route close = %v, code %s", err, CodeOf(err))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.liveCount != 0 || m.reservedBPS != 0 || m.reservedBuffers != 0 {
		t.Fatalf("leaked budget: live=%d bps=%d buffers=%d",
			m.liveCount, m.reservedBPS, m.reservedBuffers)
	}
}

func TestMaxStreamsAndExpiry(t *testing.T) {
	m, clock := newTestManager(t, nil)
	origin := testOrigin(clock, ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
	resp := beginTestTransfer(t, m, origin)
	if _, err := m.Begin(origin, &transferv1.BeginTransferRequest{
		OriginRouteId: origin.RouteID, Direction: origin.Policy.GetDirection(),
	}); CodeOf(err) != ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED {
		t.Fatalf("second Begin = %v, code %s", err, CodeOf(err))
	}

	clock.advance(6 * time.Second)
	m.reap(clock.Now())
	id, _ := parseTransferID(resp.GetProvider().GetTransferId())
	m.mu.Lock()
	state := m.records[id].state
	m.mu.Unlock()
	if state != stateClosed {
		t.Fatalf("expired PREPARED state = %v", state)
	}
}

func TestBeginRejectsDirectionEscalationAndBudgetOvercommit(t *testing.T) {
	t.Run("direction", func(t *testing.T) {
		m, clock := newTestManager(t, nil)
		origin := testOrigin(clock,
			ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
		_, err := m.Begin(origin, &transferv1.BeginTransferRequest{
			OriginRouteId: origin.RouteID,
			Direction:     ipcv1.TransferDirection_TRANSFER_DIRECTION_BIDIRECTIONAL,
		})
		if CodeOf(err) != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
			t.Fatalf("direction escalation = %v, code %s", err, CodeOf(err))
		}
	})

	t.Run("bandwidth", func(t *testing.T) {
		m, clock := newTestManager(t, func(cfg *Config) {
			cfg.Limits = Limits{
				MaxBytesPerSecond:               1024,
				MaxReservedBytesPerSecond:       512,
				MaxReservedBytesPerSecondPerUID: 512,
				MaxPacketBytes:                  1024,
				MaxRelayBufferBytes:             4096,
				ReapInterval:                    time.Hour,
			}
		})
		origin := testOrigin(clock,
			ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
		_, err := m.Begin(origin, &transferv1.BeginTransferRequest{
			OriginRouteId: origin.RouteID, Direction: origin.Policy.GetDirection(),
		})
		if CodeOf(err) != ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED {
			t.Fatalf("bandwidth overcommit = %v, code %s", err, CodeOf(err))
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.liveCount != 0 || m.reservedBPS != 0 {
			t.Fatalf("failed admission leaked budget: live=%d bps=%d",
				m.liveCount, m.reservedBPS)
		}
	})
}

func TestAbortOwnerAndIdempotence(t *testing.T) {
	m, clock := newTestManager(t, nil)
	origin := testOrigin(clock, ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
	resp := beginTestTransfer(t, m, origin)
	id := resp.GetProvider().GetTransferId()
	if err := m.Abort(999, id); CodeOf(err) != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("cross-connection Abort = %v, code %s", err, CodeOf(err))
	}
	if err := m.Abort(origin.Provider.ConnID, id); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := m.Abort(origin.Provider.ConnID, id); err != nil {
		t.Fatalf("duplicate Abort: %v", err)
	}
}

func TestListenerHandshakeConsumesTicketOnce(t *testing.T) {
	providerCred := PeerCredential{PID: 202, UID: 21002, GID: 21002}
	m, clock := newTestManager(t, func(cfg *Config) {
		cfg.PeerCredential = func(net.Conn) (PeerCredential, error) {
			return providerCred, nil
		}
	})
	origin := testOrigin(clock,
		ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
	resp := beginTestTransfer(t, m, origin)
	listener := m.ln.(*fakeListener)

	attach := func() *ipcv1.AttachTransferResult {
		t.Helper()
		server, client := net.Pipe()
		listener.accept <- server
		_ = client.SetDeadline(time.Now().Add(time.Second))
		wire, err := proto.Marshal(&ipcv1.AttachTransfer{
			TransferId:   resp.GetProvider().GetTransferId(),
			AttachTicket: resp.GetProvider().GetAttachTicket(),
			Role:         resp.GetProvider().GetRole(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeLengthFrame(client, wire); err != nil {
			t.Fatalf("write AttachTransfer: %v", err)
		}
		resultWire, err := readLengthFrame(client, attachFrameMaxBytes)
		if err != nil {
			t.Fatalf("read AttachTransferResult: %v", err)
		}
		var result ipcv1.AttachTransferResult
		if err := proto.Unmarshal(resultWire, &result); err != nil {
			t.Fatalf("unmarshal AttachTransferResult: %v", err)
		}
		_ = client.Close()
		return &result
	}

	if result := attach(); result.GetSuccess() == nil {
		t.Fatalf("first attach failed: %v", result.GetFailure())
	}
	if result := attach(); result.GetFailure().GetCode() !=
		ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED {
		t.Fatalf("ticket replay result = %v", result)
	}
}

func TestStopClosesPendingHandshake(t *testing.T) {
	m, _ := newTestManager(t, func(cfg *Config) {
		cfg.PeerCredential = func(net.Conn) (PeerCredential, error) {
			return PeerCredential{PID: 1, UID: 21001, GID: 21001}, nil
		}
		cfg.Limits = Limits{
			HandshakeTimeout: 10 * time.Second,
			ReapInterval:     time.Hour,
		}
	})
	listener := m.ln.(*fakeListener)
	server, client := net.Pipe()
	listener.accept <- server
	defer client.Close()

	deadline := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		pending := len(m.pendingConns)
		m.mu.Unlock()
		if pending == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("accepted connection never entered pending set")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop with pending handshake: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("pending handshake remained open after Stop")
	}
}

func TestTicketDigestDoesNotAcceptPrefix(t *testing.T) {
	full := bytes.Repeat([]byte{0x44}, attachTicketBytes)
	digest := ticketDigest(full)
	if ticketMatches(digest, full[:8]) {
		t.Fatal("ticket prefix matched full digest")
	}
}
