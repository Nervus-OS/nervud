package transfer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

func encodedFrame(flags uint32, payload []byte) []byte {
	wire := make([]byte, transferFrameHeaderBytes+len(payload))
	copy(wire[:4], transferFrameMagic)
	binary.BigEndian.PutUint32(wire[4:8], flags)
	binary.BigEndian.PutUint64(wire[8:16], 7)
	binary.BigEndian.PutUint64(wire[16:24], 123456)
	binary.BigEndian.PutUint32(wire[24:28], uint32(len(payload)))
	copy(wire[28:], payload)
	return wire
}

func TestNVT1FrameValidation(t *testing.T) {
	wire := encodedFrame(0, []byte("frame"))
	frame, err := readRelayFrame(bytes.NewReader(wire), make([]byte, 16), 16)
	if err != nil {
		t.Fatalf("readRelayFrame: %v", err)
	}
	var roundTrip bytes.Buffer
	if err := writeRelayFrame(&roundTrip, frame); err != nil {
		t.Fatalf("writeRelayFrame: %v", err)
	}
	if !bytes.Equal(roundTrip.Bytes(), wire) {
		t.Fatalf("round trip differs:\n got %x\nwant %x", roundTrip.Bytes(), wire)
	}

	badMagic := append([]byte(nil), wire...)
	copy(badMagic, "BAD!")
	if _, err := readRelayFrame(bytes.NewReader(badMagic), make([]byte, 16), 16); err == nil {
		t.Fatal("bad magic accepted")
	}
	if _, err := readRelayFrame(bytes.NewReader(encodedFrame(1, nil)), make([]byte, 16), 16); err == nil {
		t.Fatal("unknown flags accepted")
	}
	if _, err := readRelayFrame(bytes.NewReader(encodedFrame(0, make([]byte, 17))),
		make([]byte, 16), 16); err == nil {
		t.Fatal("oversize payload accepted")
	}
}

func TestFramedRelayProviderToCaller(t *testing.T) {
	m, clock := newTestManager(t, func(cfg *Config) {
		cfg.Limits = Limits{
			MaxFramesPerSecond: 10000,
			IdleTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ReapInterval:       time.Hour,
		}
	})
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
	callerClient, id, active, err := attachDirect(t, m, resp.GetCaller(), origin.Caller.Credential)
	if err != nil || !active {
		t.Fatalf("caller attach = active:%v err:%v", active, err)
	}
	defer callerClient.Close()
	if err := m.FinishRoute(origin.RouteID, true, []*ipcv1.TransferHandle{resp.GetCaller()}); err != nil {
		t.Fatalf("FinishRoute: %v", err)
	}
	m.startRelay(id)

	want := encodedFrame(0, []byte("camera-frame"))
	writeDone := make(chan error, 1)
	go func() {
		_, err := providerClient.Write(want)
		writeDone <- err
	}()
	got := make([]byte, len(want))
	_ = callerClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(callerClient, got); err != nil {
		t.Fatalf("read relayed frame: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write provider frame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("relay changed frame:\n got %x\nwant %x", got, want)
	}

	m.ConnClosed(origin.Provider.ConnID)
	_ = callerClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := callerClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("provider control disconnect did not close data plane")
	}
}

func TestRelayRejectsProtocolViolation(t *testing.T) {
	m, clock := newTestManager(t, func(cfg *Config) {
		cfg.Limits = Limits{
			IdleTimeout:  time.Second,
			WriteTimeout: time.Second,
			ReapInterval: time.Hour,
		}
	})
	origin := testOrigin(clock, ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER)
	resp := beginTestTransfer(t, m, origin)
	providerClient, _, _, _ := attachDirect(t, m, resp.GetProvider(), origin.Provider.Credential)
	defer providerClient.Close()
	if err := m.Commit(origin.Provider.ConnID, resp.GetProvider().GetTransferId()); err != nil {
		t.Fatal(err)
	}
	callerClient, id, _, _ := attachDirect(t, m, resp.GetCaller(), origin.Caller.Credential)
	defer callerClient.Close()
	m.startRelay(id)
	if _, err := providerClient.Write(encodedFrame(1, nil)); err != nil {
		t.Fatalf("write malformed frame: %v", err)
	}
	_ = callerClient.SetReadDeadline(time.Now().Add(time.Second))
	_, err := callerClient.Read(make([]byte, 1))
	if err == nil || errors.Is(err, io.EOF) {
		// EOF is also an acceptable close result; normalize only the nil case.
		if err == nil {
			t.Fatal("malformed frame was relayed")
		}
	}
}
