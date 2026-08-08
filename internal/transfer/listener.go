package transfer

import (
	"crypto/subtle"
	"fmt"
	"net"
	"time"

	"github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"
)

func (m *Manager) acceptLoop() {
	defer m.wg.Done()
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			select {
			case <-m.quit:
				return
			default:
			}
			m.reportFatal(fmt.Errorf("transfer: accept failed: %w", err))
			return
		}
		m.mu.Lock()
		if m.pending >= m.limits.MaxPendingAttachments || m.stopping {
			m.mu.Unlock()
			_ = conn.Close()
			continue
		}
		m.pending++
		m.pendingConns[conn] = struct{}{}
		m.mu.Unlock()
		m.wg.Add(1)
		go m.serveAttach(conn)
	}
}

func (m *Manager) serveAttach(conn net.Conn) {
	defer m.wg.Done()
	defer func() {
		m.mu.Lock()
		m.pending--
		delete(m.pendingConns, conn)
		m.mu.Unlock()
	}()

	credential, err := m.peerCred(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	m.mu.Lock()
	if m.pendingUID[credential.UID] >= m.limits.MaxPendingAttachmentsPerUID || m.stopping {
		m.mu.Unlock()
		_ = conn.Close()
		return
	}
	m.pendingUID[credential.UID]++
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if m.pendingUID[credential.UID] <= 1 {
			delete(m.pendingUID, credential.UID)
		} else {
			m.pendingUID[credential.UID]--
		}
		m.mu.Unlock()
	}()

	_ = conn.SetDeadline(m.clock.Now().Add(m.limits.HandshakeTimeout))
	wire, err := readLengthFrame(conn, attachFrameMaxBytes)
	if err != nil {
		_ = conn.Close()
		return
	}
	var req ipcv1.AttachTransfer
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(wire, &req); err != nil ||
		len(req.ProtoReflect().GetUnknown()) != 0 {
		_ = writeAttachFailure(conn, ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT)
		_ = conn.Close()
		return
	}
	success, id, active, ring, err := m.attach(conn, credential, &req)
	if err != nil {
		_ = writeAttachFailure(conn, CodeOf(err))
		_ = conn.Close()
		return
	}
	resultWire, marshalErr := proto.Marshal(&ipcv1.AttachTransferResult{
		Outcome: &ipcv1.AttachTransferResult_Success{Success: success},
	})
	if marshalErr != nil || writeLengthFrame(conn, resultWire) != nil {
		m.closeID(id, terminalPeerClosed)
		_ = conn.Close()
		return
	}
	// ring 模式: 结果帧之后紧接着用 SCM_RIGHTS 送 memfd 与 eventfd.
	//
	// 必须在结果帧之后: 对端要先从结果里读到 mode 与几何参数, 才知道
	// 该不该去收 fd, 收到之后按什么尺寸映射.
	if ring != nil {
		if err := sendRingFDs(conn, ring); err != nil {
			if m.log != nil {
				m.log.Warn("transfer: failed to hand over ring descriptors",
					"err", err)
			}
			m.closeID(id, terminalPeerClosed)
			_ = conn.Close()
			return
		}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		m.closeID(id, terminalPeerClosed)
		return
	}
	// ring 模式不起 relay: 两端 mmap 同一块内存直接收发, nervud 不在
	// 数据路径上. 起了 relay 反而会把两条控制连接当成数据流去读
	if active && success.GetMode() != ipcv1.TransferMode_TRANSFER_MODE_SHARED_MEMORY_RING {
		m.startRelay(id)
	}
	// Manager owns conn after a successful attach.
}

func writeAttachFailure(conn net.Conn, code ipcv1.StatusCode) error {
	wire, err := proto.Marshal(&ipcv1.AttachTransferResult{
		Outcome: &ipcv1.AttachTransferResult_Failure{Failure: &ipcv1.Failure{Code: code}},
	})
	if err != nil {
		return err
	}
	return writeLengthFrame(conn, wire)
}

func (m *Manager) attach(conn net.Conn, credential PeerCredential, req *ipcv1.AttachTransfer) (
	*ipcv1.AttachTransferSuccess, transferID, bool, *ringResources, error,
) {
	id, ok := parseTransferID(req.GetTransferId())
	if !ok || len(req.GetAttachTicket()) < attachTicketBytes {
		return nil, id, false, nil, status(ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED,
			"transfer: invalid attachment credential")
	}
	digest := ticketDigest(req.GetAttachTicket())
	now := m.clock.Now()
	m.mu.Lock()
	r := m.records[id]
	if r == nil || r.state == stateClosed || m.stopping {
		m.mu.Unlock()
		return nil, id, false, nil, status(ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED,
			"transfer: invalid attachment credential")
	}

	providerTicket := subtle.ConstantTimeCompare(digest[:], r.provider.ticketDigest[:]) == 1
	callerTicket := subtle.ConstantTimeCompare(digest[:], r.caller.ticketDigest[:]) == 1
	var side *transferSide
	var provider bool
	switch {
	case providerTicket && !callerTicket:
		side, provider = &r.provider, true
	case callerTicket && !providerTicket:
		side = &r.caller
	default:
		m.mu.Unlock()
		return nil, id, false, nil, status(ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED,
			"transfer: invalid attachment credential")
	}
	if side.consumed || side.conn != nil || req.GetRole() != side.role ||
		side.owner.Credential != credential {
		m.mu.Unlock()
		return nil, id, false, nil, status(ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED,
			"transfer: invalid attachment credential")
	}
	if !now.Before(side.expiresAt) {
		conns := m.closeLocked(r, terminalExpired, now)
		m.mu.Unlock()
		closeConns(conns)
		return nil, id, false, nil, status(ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED,
			"transfer: attachment ticket expired")
	}
	if provider {
		if r.state != statePrepared {
			m.mu.Unlock()
			return nil, id, false, nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
				"transfer: provider attachment is not allowed in current state")
		}
	} else if r.state != stateCommitted {
		// In particular, caller racing before Commit does not burn its ticket.
		m.mu.Unlock()
		return nil, id, false, nil, status(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"transfer: caller attachment requires Commit")
	}

	// Ticket consumption and socket ownership become visible atomically only
	// after every state/role/credential check succeeds.
	side.consumed = true
	side.conn = conn
	active := false
	if !provider {
		r.state = stateActive
		active = true
	}
	success := &ipcv1.AttachTransferSuccess{
		Mode: r.mode, MaxPacketBytes: r.maxPacket,
		MaxBytesPerSecond: r.maxBPS,
	}
	var ring *ringResources
	if r.mode == ipcv1.TransferMode_TRANSFER_MODE_SHARED_MEMORY_RING && r.ring != nil {
		success.Ring = r.ring.config
		ring = r.ring
	}
	m.mu.Unlock()
	return success, id, active, ring, nil
}

func (m *Manager) reportFatal(err error) {
	m.fatalOnce.Do(func() {
		select {
		case m.fatal <- err:
		default:
		}
	})
}

func (m *Manager) reapLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.limits.ReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.quit:
			return
		case <-ticker.C:
			m.reap(m.clock.Now())
		}
	}
}

func (m *Manager) reap(now time.Time) {
	m.mu.Lock()
	var conns []net.Conn
	for id, r := range m.records {
		switch r.state {
		case statePrepared:
			if !now.Before(r.provider.expiresAt) || !now.Before(r.deadline) {
				conns = append(conns, m.closeLocked(r, terminalExpired, now)...)
			}
		case stateCommitted:
			if !now.Before(r.caller.expiresAt) {
				conns = append(conns, m.closeLocked(r, terminalExpired, now)...)
			}
		case stateClosed:
			if now.Sub(r.terminalAt) >= m.limits.TombstoneTTL {
				delete(m.records, id)
				m.tombstones--
				if ids := m.byRoute[r.routeID]; ids != nil {
					delete(ids, id)
					if len(ids) == 0 {
						delete(m.byRoute, r.routeID)
					}
				}
			}
		case stateActive:
		}
	}
	m.mu.Unlock()
	closeConns(conns)
}
