package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func hdr(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func TestReadFrameHeader_LengthBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		n       uint32
		wantErr error
	}{
		{"zero length is invalid", 0, ErrZeroLength},
		{"minimum valid length", 1, nil},
		{"one below the limit", MaxFrameBytes - 1, nil},
		{"exactly at the limit", MaxFrameBytes, nil},
		{"one above the limit", MaxFrameBytes + 1, ErrFrameTooLarge},
		{"false 4 GiB claim", ^uint32(0), ErrFrameTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadFrameHeader(bytes.NewReader(hdr(tc.n)))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.n {
				t.Fatalf("n = %d, want %d", got, tc.n)
			}
		})
	}
}

func TestReadFrameHeader_RejectsBeforeTouchingBody(t *testing.T) {
	r := bytes.NewReader(hdr(MaxFrameBytes + 1))
	_, err := ReadFrameHeader(r)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
	if r.Len() != 0 {
		t.Fatalf("reader has %d unread bytes; the implementation consumed data beyond the header", r.Len())
	}
}

func TestReadFrame_Coalesced(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, []byte("second")); err != nil {
		t.Fatal(err)
	}

	scratch := make([]byte, MaxFrameBytes)
	for _, want := range []string{"first", "second"} {
		n, err := ReadFrameHeader(&buf)
		if err != nil {
			t.Fatalf("header: %v", err)
		}
		body, err := ReadFrameBody(&buf, scratch, n)
		if err != nil {
			t.Fatalf("body: %v", err)
		}
		if string(body) != want {
			t.Fatalf("body = %q, want %q", body, want)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("%d bytes remain unconsumed", buf.Len())
	}
}

type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

func TestReadFrame_Fragmented(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 5000)

	var wire bytes.Buffer
	if err := WriteFrame(&wire, payload); err != nil {
		t.Fatal(err)
	}
	r := &oneByteReader{data: wire.Bytes()}

	n, err := ReadFrameHeader(r)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	if n != uint32(len(payload)) {
		t.Fatalf("n = %d, want %d", n, len(payload))
	}
	body, err := ReadFrameBody(r, make([]byte, MaxFrameBytes), n)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("frame body mismatch")
	}
}

func TestReadFrameBody_Truncated(t *testing.T) {
	wire := append(hdr(100), bytes.Repeat([]byte("y"), 40)...)
	r := bytes.NewReader(wire)

	n, err := ReadFrameHeader(r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ReadFrameBody(r, make([]byte, MaxFrameBytes), n)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameHeader_CleanEOF(t *testing.T) {
	if _, err := ReadFrameHeader(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

func TestReadFrameBody_BufferTooSmall(t *testing.T) {
	r := bytes.NewReader(bytes.Repeat([]byte("z"), 100))
	if _, err := ReadFrameBody(r, make([]byte, 10), 100); err == nil {
		t.Fatal("want error when buf smaller than n")
	}
}

func TestWriteFrame_RejectsIllegalSizes(t *testing.T) {
	if err := WriteFrame(io.Discard, nil); !errors.Is(err, ErrZeroLength) {
		t.Fatalf("empty payload err = %v, want ErrZeroLength", err)
	}
	oversize := make([]byte, MaxFrameBytes+1)
	if err := WriteFrame(io.Discard, oversize); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized payload err = %v, want ErrFrameTooLarge", err)
	}
}

func TestWriteFrame_WireLayout(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	want := []byte{0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire = % x, want % x", got, want)
	}
}

type failAfterNWrites struct {
	n   int
	cnt int
}

func (w *failAfterNWrites) Write(p []byte) (int, error) {
	w.cnt++
	if w.cnt > w.n {
		return 0, errors.New("boom")
	}
	return len(p), nil
}

func TestWriteFrame_BodyWriteFailure(t *testing.T) {
	if err := WriteFrame(&failAfterNWrites{n: 1}, []byte("abc")); err == nil {
		t.Fatal("a body write failure must return an error")
	}
}
