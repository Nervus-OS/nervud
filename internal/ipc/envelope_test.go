package ipc

import (
	"errors"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
	"google.golang.org/protobuf/proto"
)

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestParseEnvelope_RoundTrip(t *testing.T) {
	in := &ipcv1.Envelope{
		Body: &ipcv1.Envelope_Ping{Ping: &ipcv1.Ping{Nonce: 42}},
	}
	env, err := parseEnvelope(mustMarshal(t, in))
	if err != nil {
		t.Fatalf("parseEnvelope: %v", err)
	}
	if got := env.GetPing().GetNonce(); got != 42 {
		t.Fatalf("nonce = %d, want 42", got)
	}
}

func TestParseEnvelope_MalformedIsViolation(t *testing.T) {
	_, err := parseEnvelope([]byte{0x08})
	if !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("err = %v, want ErrMalformedEnvelope", err)
	}
	if !isProtocolViolation(err) {
		t.Fatal("a malformed Envelope must be classified as a protocol violation")
	}
}

func TestParseEnvelope_EmptyBodyIsViolation(t *testing.T) {
	_, err := parseEnvelope(nil)
	if !errors.Is(err, ErrEmptyEnvelopeBody) {
		t.Fatalf("err = %v, want ErrEmptyEnvelopeBody", err)
	}
	if !isProtocolViolation(err) {
		t.Fatal("an empty body must be classified as a protocol violation")
	}
}

func TestParseEnvelope_VersionOnlyIsViolation(t *testing.T) {
	in := &ipcv1.Envelope{ProtocolMajor: 1, ProtocolMinor: 0}
	if _, err := parseEnvelope(mustMarshal(t, in)); !errors.Is(err, ErrEmptyEnvelopeBody) {
		t.Fatalf("err = %v, want ErrEmptyEnvelopeBody", err)
	}
}

func TestParseEnvelope_UnknownFieldIsTolerated(t *testing.T) {
	in := &ipcv1.Envelope{Body: &ipcv1.Envelope_Ping{Ping: &ipcv1.Ping{Nonce: 7}}}
	b := mustMarshal(t, in)

	b = append(b, 0xC0, 0x3E, 0x01)

	env, err := parseEnvelope(b)
	if err != nil {
		t.Fatalf("an unknown field should not make parsing fail: %v", err)
	}
	if got := env.GetPing().GetNonce(); got != 7 {
		t.Fatalf("nonce = %d, want 7 because unknown fields must not corrupt known fields", got)
	}
}

func TestParseEnvelope_UnknownBodyIsViolation(t *testing.T) {
	b := []byte{0xBA, 0x0C, 0x00}
	if _, err := parseEnvelope(b); !errors.Is(err, ErrEmptyEnvelopeBody) {
		t.Fatalf("err = %v, want ErrEmptyEnvelopeBody", err)
	}
}
