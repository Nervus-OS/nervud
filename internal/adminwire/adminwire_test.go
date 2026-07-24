package adminwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestWriteReadRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	req := Request{Cmd: CmdInstall, StagingDir: "/var/lib/nervus/staging/stage-123"}
	if err := WriteTo(&buf, req); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	var got Request
	if err := ReadFrom(&buf, &got); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got.Cmd != req.Cmd || got.StagingDir != req.StagingDir {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, req)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	resp := Response{
		OK:   true,
		Code: CodeOK,
		Package: &PackageInfo{
			ID: "com.example.app", Version: "1.0.0", VersionCode: 100,
			Trust: "ordinary", Source: "dynamic-install", Granted: []string{"perm.a"},
		},
	}
	if err := WriteTo(&buf, resp); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	var got Response
	if err := ReadFrom(&buf, &got); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !got.OK || got.Package == nil || got.Package.ID != "com.example.app" || len(got.Package.Granted) != 1 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

// 超过硬上限的长度前缀必须被拒，且【不】为其分配缓冲。
func TestReadFromRejectsOversizeHeader(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxMessageBytes+1)
	r := bytes.NewReader(hdr[:])
	var v Request
	err := ReadFrom(r, &v)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err = %v, want ErrMessageTooLarge", err)
	}
}

func TestReadFromRejectsZeroLength(t *testing.T) {
	var hdr [4]byte // 全零 = 长度 0
	var v Request
	if err := ReadFrom(bytes.NewReader(hdr[:]), &v); err == nil {
		t.Fatal("want error on zero-length message")
	}
}

func TestWriteToRejectsOversizeBody(t *testing.T) {
	big := Request{Cmd: CmdInstall, StagingDir: string(make([]byte, MaxMessageBytes+10))}
	if err := WriteTo(io.Discard, big); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err = %v, want ErrMessageTooLarge", err)
	}
}

func TestReadFromEOF(t *testing.T) {
	var v Request
	if err := ReadFrom(bytes.NewReader(nil), &v); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}
