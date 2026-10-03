//go:build linux

package socket

import (
	"context"
	"fmt"
	"log/slog"
	"nervud/internal/config"
	"net"
	"syscall"

	pb "github.com/Nervus-OS/nervus-ipc/go/v2"
)

type Connection struct {
	id        uint64
	conn      *net.UnixConn
	senderUID uint32
	ctx       context.Context
	cancel    context.CancelFunc
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
			if err.Error() == "EOF" || isConnectionClosed(err) {
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
		slog.Debug("received request", "connID", c.id, "requestID", body.Request.RequestId)
		// TODO: Handle Request

	case *pb.Envelope_Subscribe:
		slog.Debug("received subscribe", "connID", c.id, "requestID", body.Subscribe.RequestId)
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
