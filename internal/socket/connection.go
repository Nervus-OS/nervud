//go:build linux

package socket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"nervud/internal/config"
	"nervud/internal/registry"
	"nervud/internal/virtual"
	"net"
	"sync"
	"syscall"

	pb "github.com/Nervus-OS/nervus-ipc/go/v2"
)

type Connection struct {
	id        uint64
	conn      *net.UnixConn
	senderUID uint32
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// New Connection
func newConnection(ctx context.Context, connID uint64, conn *net.UnixConn) (*Connection, error) {
	// Get process UID
	uid, err := getUIDFromConn(conn)
	if err != nil {
		return nil, fmt.Errorf("get peer uid: %w", err)
	}

	connCtx, cancel := context.WithCancel(ctx)

	c := &Connection{
		id:        connID,
		conn:      conn,
		senderUID: uid,
		ctx:       connCtx,
		cancel:    cancel,
	}

	return c, nil
}

// get process UID by socket
func getUIDFromConn(conn *net.UnixConn) (uint32, error) {
	// Get conn file
	file, err := conn.File()
	if err != nil {
		return 0, fmt.Errorf("get file descriptor: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.Error("failed to close file", "error", err)
		}
	}()

	fd := int(file.Fd())

	// Call GetsockoptUcred to get SO_PEERCRED
	ucred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("GetsockoptUcred SO_PEERCRED: %w", err)
	}

	return ucred.Uid, nil
}

// Run message loop
func (c *Connection) Run() {
	defer c.Close()

	slog.Info("connection started", "connID", c.id, "uid", c.senderUID)

	for {
		select {
		case <-c.ctx.Done():
			slog.Info("connection context cancelled", "connID", c.id)
			return
		default:
		}

		// read frame
		envelope, err := readFrame(c.conn)
		if err != nil {
			// Connection closed or read error
			if errors.Is(err, io.EOF) || isConnectionClosed(err) {
				slog.Info("connection closed by peer", "connID", c.id)
			} else {
				slog.Error("read frame failed", "connID", c.id, "error", err)
			}
			return
		}

		// Handle message
		c.handleMessage(envelope)
	}
}

func (c *Connection) handleMessage(envelope *pb.Envelope) {
	// Check protocol version
	if envelope.ProtocolVersion != config.Get().ProtocolVersion {
		c.Close()
		return
	}

	// TODO: Dispatch handling based on message type
	switch body := envelope.Body.(type) {
	case *pb.Envelope_Request:
		c.fillCallerPermissions(body.Request)

		slog.Debug("received request",
			"connID", c.id,
			"requestID", body.Request.RequestId,
			"target", body.Request.TargetService,
			"method", body.Request.Method,
			"callerPerms", body.Request.CallerPermissions)

		// Handle virtual service request
		if virtual.IsVirtualService(body.Request.TargetService) {
			response := virtual.GetGlobalService().HandleRequest(body.Request, c.senderUID)

			c.sendResponse(response)
		} else {
			// TODO: Other Handle Request
		}

	case *pb.Envelope_Subscribe:
		c.fillSubscribePermissions(body.Subscribe)

		slog.Debug("received subscribe",
			"connID", c.id,
			"eventID", body.Subscribe.EventId)

		// TODO: Handle Subscribe

	case *pb.Envelope_PublishEvent:
		slog.Debug("received publish event", "connID", c.id, "eventID", body.PublishEvent.EventId)
		// TODO: Handle PublishEvent

	case *pb.Envelope_Ping:
		slog.Debug("received ping", "connID", c.id, "nonce", body.Ping.Nonce)
		// Respond with Pong
		c.sendPong(body.Ping.Nonce)

	case *pb.Envelope_Cancel:
		slog.Debug("received cancel", "connID", c.id, "requestID", body.Cancel.RequestId)
		// TODO: Handle Cancel

	default:
		slog.Warn("unknown message type", "connID", c.id)
	}
}

func (c *Connection) sendResponse(response *pb.Response) {
	envelope := &pb.Envelope{
		ProtocolVersion: config.Get().ProtocolVersion,
		Body: &pb.Envelope_Response{
			Response: response,
		},
	}

	if err := writeFrame(c.conn, envelope); err != nil {
		slog.Error("send response failed",
			"connID", c.id,
			"requestID", response.RequestId,
			"error", err)
	}
}

// fillCallerPermissions fills the CallerPermissions field in the request based on the caller's UID and the target service's permissions.
func (c *Connection) fillCallerPermissions(req *pb.Request) {
	// Get ComponentStore
	store := registry.GetGlobalStore()
	if store == nil {
		slog.Warn("component store not initialized")
		req.CallerPermissions = []string{}
		return
	}

	// Query the caller component by UID
	caller := store.GetComponentByUID(int32(c.senderUID))
	if caller == nil {
		slog.Warn("caller component not found", "uid", c.senderUID)
		req.CallerPermissions = []string{}
		return
	}

	// Query target service component
	target := store.GetComponent(req.TargetService)
	if target == nil {
		slog.Warn("target service not found", "service", req.TargetService)
		req.CallerPermissions = []string{}
		return
	}

	// Filter permissions retaining the target service statement
	var filteredPerms []string
	for _, callerPerm := range caller.Permissions {
		// Skip unconfirmed permissions
		if !callerPerm.IsConfirmed {
			continue
		}

		// Check if the caller's permission is in the target's permission additions
		for _, addedPerm := range target.PermissionAdditions {
			if addedPerm.ID == callerPerm.ID {
				filteredPerms = append(filteredPerms, callerPerm.ID)
				break
			}
		}
	}

	// Fill
	req.CallerPermissions = filteredPerms
}

// fillSubscribePermissions fills the CallerPermissions field in the subscription message based on the caller's UID and the event's permissions.
func (c *Connection) fillSubscribePermissions(sub *pb.Subscribe) {
	// Get ComponentStore
	store := registry.GetGlobalStore()
	if store == nil {
		slog.Warn("component store not initialized")
		sub.CallerPermissions = []string{}
		return
	}

	// TODO: Extract the service ID from the event_id.
	// Format: com.example.service.event.battery_low → com.example.service
	// Temporarily simplified handling
	sub.CallerPermissions = []string{}
}

// sendPong sends a Pong response
func (c *Connection) sendPong(nonce uint64) {
	envelope := &pb.Envelope{
		ProtocolVersion: config.Get().ProtocolVersion,
		Body: &pb.Envelope_Pong{
			Pong: &pb.Pong{
				Nonce: nonce,
			},
		},
	}

	if err := writeFrame(c.conn, envelope); err != nil {
		slog.Error("send pong failed", "connID", c.id, "error", err)
	}
}

// SendResponse sends a response envelope to the client
func (c *Connection) SendResponse(envelope *pb.Envelope) error {
	return writeFrame(c.conn, envelope)
}

// Close connection
func (c *Connection) Close() {
	c.cancel()
	if err := c.conn.Close(); err != nil {
		slog.Error("close connection failed", "connID", c.id, "error", err)
	}
	slog.Info("connection closed", "connID", c.id)
}

// isConnectionClosed checks if the error indicates that the connection is closed
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	// Check for specific error messages that indicate a closed connection
	errStr := err.Error()
	return errStr == "use of closed network connection" ||
		errStr == "connection reset by peer"
}
