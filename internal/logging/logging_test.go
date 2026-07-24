package logging

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type blockingWriter struct {
	release chan struct{}
	writes  chan []byte
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{release: make(chan struct{}), writes: make(chan []byte, 64)}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	<-w.release
	b := make([]byte, len(p))
	copy(b, p)
	w.writes <- b
	return len(p), nil
}

func TestAsyncWriter_DeliversAll(t *testing.T) {
	dst := &syncBuffer{}
	w := NewAsyncWriter(dst, 128)

	for _, s := range []string{"alpha\n", "beta\n", "gamma\n"} {
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	got := dst.String()
	for _, s := range []string{"alpha", "beta", "gamma"} {
		if !bytes.Contains([]byte(got), []byte(s)) {
			t.Fatalf("output is missing %q, got %q", s, got)
		}
	}
}

func TestAsyncWriter_WriteNeverBlocksWhenSinkStuck(t *testing.T) {
	bw := newBlockingWriter()
	w := NewAsyncWriter(bw, 4)

	done := make(chan struct{})
	go func() {
		for range 1000 {
			_, _ = w.Write([]byte("x\n"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked when dst stalled")
	}

	if w.Dropped() == 0 {
		t.Fatal("queue should be full and dropping records, but dropped is 0")
	}
}

func TestAsyncWriter_CloseHonoursTimeoutWhenSinkStuck(t *testing.T) {
	bw := newBlockingWriter()
	w := NewAsyncWriter(bw, 4)
	w.flushTimeout = 100 * time.Millisecond

	_, _ = w.Write([]byte("stuck\n"))
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	_ = w.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %v; flushTimeout did not take effect", elapsed)
	}
}

func TestAsyncWriter_CloseIdempotent(t *testing.T) {
	w := NewAsyncWriter(&syncBuffer{}, 8)
	_ = w.Close()
	_ = w.Close()
}

func TestAsyncWriter_ConcurrentWriters(t *testing.T) {
	dst := &syncBuffer{}
	w := NewAsyncWriter(dst, 4096)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range 100 {
				_, _ = w.Write([]byte{byte('A' + id), '\n'})
			}
		}(g)
	}
	wg.Wait()
	_ = w.Close()

	if d := w.Dropped(); d != 0 {
		t.Fatalf("dropped %d records despite sufficient queue capacity", d)
	}
}
