package transfer

import (
	"net"
	"sync"
	"time"

	"github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

type transferID [transferIDBytes]byte

func parseTransferID(wire []byte) (transferID, bool) {
	var id transferID
	if len(wire) != len(id) {
		return id, false
	}
	copy(id[:], wire)
	return id, true
}

type lifecycleState uint8

const (
	statePrepared lifecycleState = iota + 1
	stateCommitted
	stateActive
	stateClosed
)

type terminalReason uint8

const (
	terminalNone terminalReason = iota
	terminalExplicitAbort
	terminalRouteFailed
	terminalUnreferenced
	terminalExpired
	terminalPeerClosed
	terminalProtocol
	terminalRevoked
	terminalStopped
)

type transferSide struct {
	owner        Peer
	role         ipcv1.TransferRole
	ticketDigest [32]byte
	expiresAt    time.Time
	expiresMono  uint64
	consumed     bool
	conn         net.Conn
}

type record struct {
	id            transferID
	routeID       uint64
	token         *RouteToken
	deadline      time.Time
	endpointID    uint64
	generation    uint64
	resource      string
	resourceGen   uint64
	permissions   []string
	requiresLease bool

	direction         ipcv1.TransferDirection
	mode              ipcv1.TransferMode
	maxPacket         uint32
	maxBPS            uint64
	bufferReservation uint64

	provider transferSide
	caller   transferSide

	state          lifecycleState
	originFinished bool
	retained       bool
	everCommitted  bool
	relayStarted   bool
	terminal       terminalReason
	terminalAt     time.Time
	budgeted       bool
	bufferBudgeted bool
	relayWorkers   int
	done           chan struct{}
	doneOnce       sync.Once
	pacer          *pacer

	// ring 只在 mode == SHARED_MEMORY_RING 时非空. 持有 memfd 与 eventfd,
	// 在 Transfer 关闭时释放.
	//
	// ring 模式下 nervud 不在数据路径上: 两端 mmap 同一块内存直接收发,
	// 没有 relay goroutine, 也没有逐帧的限速 - 限速在 ring 的几何上 (slot 数 x
	// slot 大小就是最大在途量). 这正是它相对 FRAMED_RELAY 的意义.
	ring *ringResources
}

func (r *record) peerUIDs() []uint32 {
	if r.provider.owner.Credential.UID == r.caller.owner.Credential.UID {
		return []uint32{r.provider.owner.Credential.UID}
	}
	return []uint32{
		r.provider.owner.Credential.UID,
		r.caller.owner.Credential.UID,
	}
}

func (r *record) closeSignal() {
	r.doneOnce.Do(func() { close(r.done) })
}

func rolesFor(direction ipcv1.TransferDirection) (provider, caller ipcv1.TransferRole, ok bool) {
	switch direction {
	case ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER:
		return ipcv1.TransferRole_TRANSFER_ROLE_PRODUCER,
			ipcv1.TransferRole_TRANSFER_ROLE_CONSUMER, true
	case ipcv1.TransferDirection_TRANSFER_DIRECTION_CALLER_TO_PROVIDER:
		return ipcv1.TransferRole_TRANSFER_ROLE_CONSUMER,
			ipcv1.TransferRole_TRANSFER_ROLE_PRODUCER, true
	case ipcv1.TransferDirection_TRANSFER_DIRECTION_BIDIRECTIONAL:
		return ipcv1.TransferRole_TRANSFER_ROLE_PEER,
			ipcv1.TransferRole_TRANSFER_ROLE_PEER, true
	default:
		return 0, 0, false
	}
}

func directionAllowed(policy, requested ipcv1.TransferDirection) bool {
	if _, _, ok := rolesFor(requested); !ok {
		return false
	}
	return policy == requested ||
		policy == ipcv1.TransferDirection_TRANSFER_DIRECTION_BIDIRECTIONAL
}

func relayDirections(direction ipcv1.TransferDirection) uint64 {
	if direction == ipcv1.TransferDirection_TRANSFER_DIRECTION_BIDIRECTIONAL {
		return 2
	}
	return 1
}
