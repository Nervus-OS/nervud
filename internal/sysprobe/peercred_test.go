//go:build linux

package sysprobe

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func dialSelf(t *testing.T) *net.UnixConn {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "t.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	t.Cleanup(func() { _ = a.conn.Close() })

	server, ok := a.conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("accept returned %T, want *net.UnixConn", a.conn)
	}
	return server
}

func TestPeerCred_SelfConnect(t *testing.T) {
	cred, err := PeerCred(dialSelf(t))
	if err != nil {
		t.Fatalf("PeerCred: %v", err)
	}

	if got, want := int(cred.PID), os.Getpid(); got != want {
		t.Errorf("PID = %d, want %d", got, want)
	}
	if got, want := int(cred.UID), os.Getuid(); got != want {
		t.Errorf("UID = %d, want %d", got, want)
	}
	if got, want := int(cred.GID), os.Getgid(); got != want {
		t.Errorf("GID = %d, want %d", got, want)
	}
}

func TestPeerCred_PreservesDeadlines(t *testing.T) {
	server := dialSelf(t)

	if _, err := PeerCred(server); err != nil {
		t.Fatalf("PeerCred: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err := server.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err = %v, want os.ErrDeadlineExceeded", err)
	}
}

func TestPeerCred_NilConn(t *testing.T) {
	if _, err := PeerCred(nil); err == nil {
		t.Fatal("want error for nil conn")
	}
}
