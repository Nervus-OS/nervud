package transfer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	transferFrameHeaderBytes = 28
	attachFrameMaxBytes      = 4096
	transferFrameMagic       = "NVT1"
)

type relayFrame struct {
	header  [transferFrameHeaderBytes]byte
	payload []byte
}

func readRelayFrame(r io.Reader, storage []byte, maxPacket uint32) (relayFrame, error) {
	var frame relayFrame
	if _, err := io.ReadFull(r, frame.header[:]); err != nil {
		return relayFrame{}, err
	}
	if !bytes.Equal(frame.header[0:4], []byte(transferFrameMagic)) {
		return relayFrame{}, errors.New("transfer: invalid NVT1 magic")
	}
	if flags := binary.BigEndian.Uint32(frame.header[4:8]); flags != 0 {
		return relayFrame{}, fmt.Errorf("transfer: unknown NVT1 flags %#x", flags)
	}
	n := binary.BigEndian.Uint32(frame.header[24:28])
	if n > maxPacket || uint64(n) > uint64(len(storage)) {
		return relayFrame{}, fmt.Errorf("transfer: NVT1 payload %d exceeds limit %d", n, maxPacket)
	}
	frame.payload = storage[:int(n)]
	if _, err := io.ReadFull(r, frame.payload); err != nil {
		return relayFrame{}, err
	}
	return frame, nil
}

func writeRelayFrame(w io.Writer, frame relayFrame) error {
	if err := writeAll(w, frame.header[:]); err != nil {
		return err
	}
	return writeAll(w, frame.payload)
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func readLengthFrame(r io.Reader, max uint32) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > max {
		return nil, fmt.Errorf("transfer: handshake frame length %d outside 1..%d", n, max)
	}
	body := make([]byte, int(n))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeLengthFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 || uint64(len(payload)) > uint64(^uint32(0)) {
		return errors.New("transfer: invalid handshake frame length")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}
