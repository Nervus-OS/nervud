package transfer

import (
	"errors"
	"net"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

func (m *Manager) startRelay(id transferID) {
	m.mu.Lock()
	r := m.records[id]
	if r == nil || r.state != stateActive || r.relayStarted ||
		r.provider.conn == nil || r.caller.conn == nil {
		m.mu.Unlock()
		return
	}
	r.relayStarted = true
	provider, caller := r.provider.conn, r.caller.conn
	direction, maxPacket, done := r.direction, r.maxPacket, r.done
	pacer := r.pacer
	r.relayWorkers = int(relayDirections(direction))
	m.mu.Unlock()

	switch direction {
	case ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER:
		halfCloseWrite(provider)
		halfCloseRead(caller)
		m.spawnRelay(id, provider, caller, maxPacket, pacer, done)
	case ipcv1.TransferDirection_TRANSFER_DIRECTION_CALLER_TO_PROVIDER:
		halfCloseWrite(caller)
		halfCloseRead(provider)
		m.spawnRelay(id, caller, provider, maxPacket, pacer, done)
	case ipcv1.TransferDirection_TRANSFER_DIRECTION_BIDIRECTIONAL:
		m.spawnRelay(id, provider, caller, maxPacket, pacer, done)
		m.spawnRelay(id, caller, provider, maxPacket, pacer, done)
	default:
		m.closeID(id, terminalProtocol)
	}
}

func (m *Manager) spawnRelay(
	id transferID, source, target net.Conn, maxPacket uint32, pacer *pacer, done <-chan struct{},
) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer m.relayDone(id)
		if err := m.relay(source, target, maxPacket, pacer, done); err != nil {
			m.closeID(id, terminalProtocol)
		}
	}()
}

func (m *Manager) relay(
	source, target net.Conn, maxPacket uint32, pacer *pacer, done <-chan struct{},
) error {
	storage := make([]byte, int(maxPacket))
	for {
		if err := source.SetReadDeadline(m.clock.Now().Add(m.limits.IdleTimeout)); err != nil {
			return err
		}
		frame, err := readRelayFrame(source, storage, maxPacket)
		if err != nil {
			return err
		}
		wireBytes := uint64(transferFrameHeaderBytes + len(frame.payload))
		delay, err := pacer.reserve(m.clock.Now(), wireBytes, m.limits.WriteTimeout)
		if err != nil {
			return err
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-done:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return errors.New("transfer: closed while rate limited")
			case <-m.quit:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return ErrStopped
			}
		}
		if err := target.SetWriteDeadline(m.clock.Now().Add(m.limits.WriteTimeout)); err != nil {
			return err
		}
		if err := writeRelayFrame(target, frame); err != nil {
			return err
		}
	}
}

func (m *Manager) closeID(id transferID, reason terminalReason) {
	now := m.clock.Now()
	m.mu.Lock()
	conns := m.closeLocked(m.records[id], reason, now)
	m.mu.Unlock()
	closeConns(conns)
}

func (m *Manager) relayDone(id transferID) {
	m.mu.Lock()
	r := m.records[id]
	if r != nil && r.relayWorkers > 0 {
		r.relayWorkers--
		if r.relayWorkers == 0 {
			m.releaseBufferLocked(r)
		}
	}
	m.mu.Unlock()
}

type closeReader interface{ CloseRead() error }
type closeWriter interface{ CloseWrite() error }

func halfCloseRead(conn net.Conn) {
	if c, ok := conn.(closeReader); ok {
		_ = c.CloseRead()
	}
}

func halfCloseWrite(conn net.Conn) {
	if c, ok := conn.(closeWriter); ok {
		_ = c.CloseWrite()
	}
}
