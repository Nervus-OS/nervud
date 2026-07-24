// 本文件是的分帧层：控制面 Frame 的字节布局读写
//
// Frame layout: 4-byte big-endian uint32 N, followed by N bytes of Protobuf Envelope.
//
// 本层不解码 Envelope，也不认识 endpoint/method，只把字节流切成完整的
// Envelope 字节块。这样分层让它可以在 net.Pipe 上完整测试，不需要真 socket
package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxFrameBytes 是整个控制面 Frame 的绝对硬上限
// 128 KiB = 131072 字节，不是含义模糊的 128 kb
//
// 这是 Frame 上限，不是方法额度：普通 RPC 默认 16 KiB、Safety 方法 4 KiB、
// 配置/manifest 64 KiB，逐方法在 Registry 声明，由上层取三者最小值
// 系统 Service 也不能绕过本上限
//
// 本值必须与握手时下发给客户端的 ConnectionLimits.max_frame_bytes 一致
const MaxFrameBytes = 128 << 10

// lengthPrefixBytes 是长度前缀自身的字节数。N 不包含这 4 字节
const lengthPrefixBytes = 4

// 本层的错误全部是协议违规：出现即关闭连接，不生成 Response
//
// 理由：长度字段一旦不可信，后续 Frame 的边界就无法确定，这条连接上的字节流
// 已经失去意义，回一条错误响应也无处安放 - 它自己也要靠长度前缀才能被读到
var (
	ErrZeroLength    = errors.New("ipc: frame length is zero")
	ErrFrameTooLarge = errors.New("ipc: frame length exceeds hard limit")
)

// ReadFrameHeader 读满 4 字节长度前缀并校验，返回正文长度 N
//
// 它与 ReadFrameBody 必须成对调用，中间那一刻是设置正文 deadline 的唯一时机，
// 也是本层拆成两个函数的全部理由：
//
//	空闲 deadline - 等下一个 Frame 到来，可以很长（由 Ping/Pong 维持）
//	正文 deadline - 已经宣称有 N 字节在路上，必须很短
//
// 用一个 deadline 同时覆盖两段，等于把空闲容忍度送给了 slowloris：攻击者发完
// 4 字节长度后每秒挤一个字节，就能长期占住连接、goroutine 和读缓冲
func ReadFrameHeader(r io.Reader) (uint32, error) {
	var hdr [lengthPrefixBytes]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// 含 io.EOF：对端正常关闭。调用方据此区分正常断开与异常
		return 0, err
	}

	n := binary.BigEndian.Uint32(hdr[:])
	switch {
	case n == 0:
		return 0, ErrZeroLength
	case n > MaxFrameBytes:
		// 超限立即返回，不分配、也不为了把连接读干净去排空攻击者自称的正文
		// - 那正是他想要的免费带宽和 CPU。此刻正文一个字节都还没碰过
		return 0, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, MaxFrameBytes)
	}
	return n, nil
}

// ReadFrameBody 读满 n 字节正文到 buf，返回可用切片 buf[:n]
//
// buf 由调用方提供并按连接复用，因此稳态下本函数零堆分配
// n 必须来自同一连接上刚刚成功返回的 ReadFrameHeader
//
// 一次 read 可能只带回半个 Frame，也可能一次带回好几个：UDS 是字节流，
// read 的返回边界不是消息边界，所以必须 ReadFull
func ReadFrameBody(r io.Reader, buf []byte, n uint32) ([]byte, error) {
	if int(n) > len(buf) {
		// 调用方给的 buf 小于硬上限，属于本端装配错误，不是对端的错
		return nil, fmt.Errorf("ipc: read buffer too small: need %d, have %d", n, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		// 长度已读到、正文没读满 = 对端截断或正文 deadline 到期
		// ReadFull 读到 0 字节返回 EOF，读到一部分返回 ErrUnexpectedEOF
		return nil, err
	}
	return buf[:n], nil
}

// WriteFrame 写出长度 + 正文
//
// 调用约束：每条连接只能有一个 writer goroutine 调用本函数。本函数不加锁，
// 也不打算加 - 两个 goroutine 并发写同一个 stream，哪怕各自一次 Write 写满，
// 两个 Frame 的字节也会交错，接收方从此再也找不回边界。串行化是连接层的职责
//
// w 应当是 writer goroutine 持有的缓冲 writer，让长度与正文合并成一次系统调用。
// UDS 没有 Nagle，拆成两次不会有延迟病理，只是白白多一次 syscall
//
// 返回错误时调用方必须关闭连接，不能重试本帧：长度可能已经写出去而正文没有，
// 对端的解析器正卡在等待 N 字节，这条流已经无法恢复
func WriteFrame(w io.Writer, payload []byte) error {
	n := len(payload)
	switch {
	case n == 0:
		// 本端的 bug：不要把违规帧发给对端
		return ErrZeroLength
	case n > MaxFrameBytes:
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, MaxFrameBytes)
	}

	var hdr [lengthPrefixBytes]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(n))

	// io.Writer 的契约已规定 n < len(p) 时必须返回非 nil error，
	// 因此不需要手写重试循环，只需不吞掉 error
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("ipc: write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("ipc: write frame body: %w", err)
	}
	return nil
}
