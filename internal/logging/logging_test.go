package logging

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// syncBuffer 是并发安全的 bytes.Buffer，供后台 writer goroutine 与测试断言共享
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

// blockingWriter 的 Write 阻塞到 release 关闭，用来模拟卡死的 stderr/journald
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

// 正常路径：写入的内容最终都落到 dst
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
			t.Fatalf("输出缺少 %q，实际=%q", s, got)
		}
	}
}

// 核心性质：dst 完全卡死时，Write 仍然立即返回，绝不阻塞调用方。
// 这条不成立，RT Lane 和停机路径就会被日志拖死
func TestAsyncWriter_WriteNeverBlocksWhenSinkStuck(t *testing.T) {
	bw := newBlockingWriter() // Write 永远阻塞（从不 release）
	w := NewAsyncWriter(bw, 4)

	done := make(chan struct{})
	go func() {
		// 远多于队列深度：多出来的会被丢弃，但每次 Write 都必须立即返回
		for range 1000 {
			_, _ = w.Write([]byte("x\n"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dst 卡死时 Write 被阻塞了——正是本包要消除的失效")
	}

	// 队列深度 4，写了 1000 条，绝大多数应被丢弃而不是堆积或阻塞
	if w.Dropped() == 0 {
		t.Fatal("队列早该满并开始丢弃，dropped 却是 0")
	}
}

// Close 必须在 flushTimeout 内返回，即便后台 goroutine 正卡在 dst.Write 上。
// 否则进程退出本身又被日志卡住，退出上限失效
func TestAsyncWriter_CloseHonoursTimeoutWhenSinkStuck(t *testing.T) {
	bw := newBlockingWriter()
	w := NewAsyncWriter(bw, 4)
	w.flushTimeout = 100 * time.Millisecond

	// 塞一条，后台 goroutine 会卡在 bw.Write 上
	_, _ = w.Write([]byte("stuck\n"))
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	_ = w.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close 耗时 %v，flushTimeout 没有生效", elapsed)
	}
}

// Close 幂等：可安全多次调用，不 panic（close of closed channel）
func TestAsyncWriter_CloseIdempotent(t *testing.T) {
	w := NewAsyncWriter(&syncBuffer{}, 8)
	_ = w.Close()
	_ = w.Close()
}

// 并发写入下无数据竞争（-race 下才有意义），且所有内容不丢地落盘
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

	// 队列 4096 足以容纳 800 条，不该有丢弃
	if d := w.Dropped(); d != 0 {
		t.Fatalf("队列足够大却丢了 %d 条", d)
	}
}
