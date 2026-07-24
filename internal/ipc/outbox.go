// 本文件实现每条连接独立的有界 outbound 队列
//
// Dispatch 转发要求"连接 A 处理 Request 时,把 Dispatch 写到连接 B 的 socket" -
// 这是一次跨连接写,只有 B 自己的 writer goroutine 能安全执行它（frame.go 的
// WriteFrame 约定每条连接只能有一个 writer）。本文件把这一点变成通用机制:任何
// goroutine 都可以安全地把一个 Envelope push 进某条连接的 outbox,实际的 socket
// 写出永远只在该连接自己的 writer goroutine里发生（见 conn.go 的 runWriter）
package ipc

import (
	"sync"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
	"google.golang.org/protobuf/proto"
)

// outboundQueue 是单条连接的有界 outbound 队列,按字节数而非消息条数限界
// （ 明确禁止只按消息条数计的无界队列）。push 永不阻塞调用方 - 调用方可能
// 是另一条连接的 goroutine（转发 Dispatch 时）,阻塞它等于让一个慢消费者拖住
// 无关连接
type outboundQueue struct {
	mu       sync.Mutex
	items    []*ipcv1.Envelope
	bytes    int
	maxBytes int
	closed   bool

	// wake 是容量 1 的门铃:push/close 用非阻塞 send 通知 writer "有新东西了/
	// 该退出了"。writer 醒来后总是回到锁下重新检查队列状态,因此多余的/提前的
	// 唤醒只会导致一次无害的空转,不需要精确对应每一次 push
	wake chan struct{}
}

func newOutboundQueue(maxBytes int) *outboundQueue {
	return &outboundQueue{maxBytes: maxBytes, wake: make(chan struct{}, 1)}
}

// push 尝试把 env 加入队列。队列已关闭、或加入后会超出 maxBytes,一律返回
// false - 不做任何"踢掉旧消息腾地方"的尝试:架构要求 RPC Response 不得静默
// 丢弃,满了就是满了,由调用方决定如何处理（通常是把这条连接当慢消费者关闭）
func (q *outboundQueue) push(env *ipcv1.Envelope) bool {
	size := proto.Size(env)

	q.mu.Lock()
	if q.closed || q.bytes+size > q.maxBytes {
		q.mu.Unlock()
		return false
	}
	q.items = append(q.items, env)
	q.bytes += size
	q.mu.Unlock()

	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// pop 阻塞直到队列非空或已关闭且已排空。后一种情况返回 (nil, false)
//
// 关闭不会截断已经排队的条目:close 只挡新的 push,已经进队的内容仍会被逐一
// 弹出并写出 - 这样一条连接的正常收尾（发完最后一个 Response 再关）与错误收尾
// （socket 已经写不进去了）都能被同一套逻辑覆盖,不需要区分对待
func (q *outboundQueue) pop() (*ipcv1.Envelope, bool) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			env := q.items[0]
			q.items[0] = nil // 不持有已出队 envelope 的引用,帮 GC
			q.items = q.items[1:]
			q.bytes -= proto.Size(env)
			q.mu.Unlock()
			return env, true
		}
		if q.closed {
			q.mu.Unlock()
			return nil, false
		}
		q.mu.Unlock()
		<-q.wake
	}
}

// close 标记队列不再接受新 push,并唤醒可能阻塞在 pop 里的 writer。
// 幂等:重复调用是安全的（serve 的清理路径与 writer 自身的错误路径都可能
// 触发它）
func (q *outboundQueue) close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	q.mu.Unlock()

	select {
	case q.wake <- struct{}{}:
	default:
	}
}
