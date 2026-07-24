// Package logging 提供一个非阻塞、有界、满则丢弃的日志 writer
//
// # 为什么内核需要它
//
// 默认的 slog handler 直接同步写 stderr。一旦 stderr / journald 变慢或卡住
// （管道无人读、磁盘满、journald 重启），任何写日志的 goroutine 都会被阻塞在
// 那次 write 上。对普通服务这只是延迟，对 nervud 是安全问题：
//
//   - 实时 Lane 在 RT 优先级线程上写一行生命周期日志，就可能被拖住，
//     而它本该尽快让出 CPU；
//   - 更糟的是停机路径 - 如果某个 goroutine 卡在持有 handler 锁的同步 write 上，
//     停机时 main / kernel 再调同一个 logger 就会一起卡在那把锁上，
//     laneStopTimeout / moduleStopTimeout 之类的退出上限统统失效。
//
// AsyncWriter 把 write 从调用方线程上摘下来：调用方只把字节塞进一个有界队列
// （非阻塞），一个独立 goroutine 负责真正落盘。队列满时丢弃并计数，
// 而不是阻塞 - 对 TCB 来说，丢几行日志远好于卡住一条安全路径
package logging

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// defaultFlushTimeout 是 Close 等待队列排空的上限
//
// Close 发生在进程退出前。即便底层 writer 已经完全卡死，Close 也必须在这个上限
// 内返回，否则退出本身又被日志卡住 - 那正是本包要消除的失效
const defaultFlushTimeout = 500 * time.Millisecond

// AsyncWriter 是一个非阻塞的 io.Writer 包装
//
// 并发安全：Write 可被任意多个 goroutine 同时调用（slog handler 本就可能来自
// 多个模块 goroutine）
type AsyncWriter struct {
	dst io.Writer

	queue chan []byte
	stop  chan struct{}
	done  chan struct{}

	stopOnce     sync.Once
	dropped      atomic.Uint64
	flushTimeout time.Duration
}

// NewAsyncWriter 起一个后台 goroutine 把 queue 里的字节写到 dst
//
// queueDepth 是队列能暂存的消息条数。它不是字节预算：日志行长度有限，
// 用条数足够，也更好推理。深度越大越不容易丢日志，但占用内存越多、
// 停机 flush 越久
func NewAsyncWriter(dst io.Writer, queueDepth int) *AsyncWriter {
	if queueDepth < 1 {
		queueDepth = 1
	}
	w := &AsyncWriter{
		dst:          dst,
		queue:        make(chan []byte, queueDepth),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		flushTimeout: defaultFlushTimeout,
	}
	go w.run()
	return w
}

// Write 把 p 拷贝后塞进队列，永不阻塞
//
// 必须拷贝：slog 复用它传入的 buffer，Write 返回后 p 的内容随时可能被覆写，
// 而真正的落盘发生在另一个 goroutine 上、晚于本次返回
//
// 返回值恒为 (len(p), nil)：即便这一行被丢弃，也不告诉 slog 出错 - 日志写失败
// 不该让业务逻辑拿到一个 error 去处理，那只会把日志问题扩散成业务问题
func (w *AsyncWriter) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)

	select {
	case w.queue <- b:
	case <-w.stop:
		// 已进入关闭：绕过队列直接同步写，尽力让退出期的最后几行日志可见。
		// 此时进程正在退出，短暂的同步阻塞可接受，且 Close 有 flushTimeout 兜底
		_, _ = w.dst.Write(p)
	default:
		// 队列满：丢弃并计数。绝不阻塞调用方 - 这正是本包存在的理由
		w.dropped.Add(1)
	}
	return len(p), nil
}

func (w *AsyncWriter) run() {
	defer close(w.done)
	for {
		select {
		case b := <-w.queue:
			_, _ = w.dst.Write(b) // 日志尽力而为，写失败无处上报也不该 panic
		case <-w.stop:
			// 排空队列里剩余的，然后退出
			for {
				select {
				case b := <-w.queue:
					_, _ = w.dst.Write(b)
				default:
					return
				}
			}
		}
	}
}

// Dropped 返回累计丢弃的日志条数，供停机时记录一笔
func (w *AsyncWriter) Dropped() uint64 { return w.dropped.Load() }

// Close 停掉后台 goroutine，并在 flushTimeout 内尽力排空队列
//
// 幂等。超时即返回，绝不无限等待 - 退出路径本身不能被日志卡住
func (w *AsyncWriter) Close() error {
	w.stopOnce.Do(func() { close(w.stop) })
	select {
	case <-w.done:
	case <-time.After(w.flushTimeout):
	}
	return nil
}
