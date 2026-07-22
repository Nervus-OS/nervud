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

// dialSelf 起一个 UDS listener 并自己连上去，返回服务端侧的连接
// 自连是单进程内能做到的最强断言场景：对端的 PID/UID/GID 就是本进程的
// 可以逐个精确比对，而不是只断言 拿到了非零值
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
	ch := make(chan accepted, 1) // 容量 1：Accept 失败时 goroutine 也不会泄漏
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

// TestPeerCred_PreservesDeadlines 是一条回归锁，盯的是实现方式而不是返回值
//
// 如果有人把 PeerCred 改成用 c.File() 取 fd，File() 会 dup 一份 fd 并把原连接
// 切成阻塞模式，netpoller 从此不再管这条连接，SetReadDeadline 静默失效——
// 下面这个 Read 会永远挂住（由 go test 的超时兜底），而不是按期返回超时错误
//
// 控制面的 slowloris 防护完全建立在 deadline 上（§10.11），所以这条性质必须
// 被测试锁住，不能只写在注释里
func TestPeerCred_PreservesDeadlines(t *testing.T) {
	server := dialSelf(t)

	if _, err := PeerCred(server); err != nil {
		t.Fatalf("PeerCred: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	// 对端已连接但从不发送数据：唯一能让 Read 返回的就是 deadline。
	_, err := server.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err = %v, want os.ErrDeadlineExceeded", err)
	}
}

func TestPeerCred_NilConn(t *testing.T) {
	// 明确报错而不是 panic：nil 连接是调用方的装配错误，应当能被上层记录并定位，不该让整个内核崩掉
	if _, err := PeerCred(nil); err == nil {
		t.Fatal("want error for nil conn")
	}
}
