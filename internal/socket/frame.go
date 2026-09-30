package socket

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	pb "github.com/Nervus-OS/nervus-ipc/go/v2"
	"google.golang.org/protobuf/proto"
)

const (
	// Maximum frame size: 4MB
	maxFrameSize = 4 * 1024 * 1024

	// Read/Write timeout
	ioTimeout = 30 * time.Second
)

// writeFrame writes an Envelope to conn as a framed message.
// Frame format: [4-byte length in big-endian][protobuf message body]
func writeFrame(conn net.Conn, envelope *pb.Envelope) error {
	// Serialize envelope to protobuf
	data, err := proto.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	// Check size limit
	if len(data) > maxFrameSize {
		return fmt.Errorf("frame too large: %d bytes", len(data))
	}

	// Set write deadline
	if err := conn.SetWriteDeadline(time.Now().Add(ioTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}

	// Write length (4 bytes, big-endian)
	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}

	// Write message body
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write frame data: %w", err)
	}

	return nil
}

// readFrame reads a framed Envelope from conn.
func readFrame(conn net.Conn) (*pb.Envelope, error) {
	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	// Read length (4 bytes, big-endian)
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}

	// Check size limit
	if length > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}

	// Read message body
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("read frame data: %w", err)
	}

	// Deserialize protobuf
	envelope := &pb.Envelope{}
	if err := proto.Unmarshal(data, envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	return envelope, nil
}
