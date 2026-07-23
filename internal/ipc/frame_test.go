package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// hdr 构造一个 4 字节大端长度前缀
func hdr(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

// --- 长度边界 -------------------------------------------------------------

// 边界只测超限不测刚好是经典漏测：off-by-one 正好藏在等号上，
// 所以 131071 / 131072 / 131073 三个点都要覆盖
func TestReadFrameHeader_LengthBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		n       uint32
		wantErr error
	}{
		{"零长度即违规", 0, ErrZeroLength},
		{"最小合法", 1, nil},
		{"上限减一", MaxFrameBytes - 1, nil},
		{"恰好上限", MaxFrameBytes, nil},
		{"上限加一", MaxFrameBytes + 1, ErrFrameTooLarge},
		{"4GiB 谎报", ^uint32(0), ErrFrameTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadFrameHeader(bytes.NewReader(hdr(tc.n)))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.n {
				t.Fatalf("n = %d, want %d", got, tc.n)
			}
		})
	}
}

// 这条锁的是安全属性本身而不是返回值：超限时必须在【没有读走正文任何字节】
// 的情况下就返回错误。做法是只喂 4 字节头、正文一个字节都不给——如果实现
// 先分配再读，这里会拿到 EOF/ErrUnexpectedEOF 而不是 ErrFrameTooLarge
func TestReadFrameHeader_RejectsBeforeTouchingBody(t *testing.T) {
	r := bytes.NewReader(hdr(MaxFrameBytes + 1))
	_, err := ReadFrameHeader(r)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
	if r.Len() != 0 {
		t.Fatalf("reader 还剩 %d 字节未读，说明实现读了头以外的东西", r.Len())
	}
}

// --- 粘包 / 半包 ----------------------------------------------------------

// 粘包：一次写入两个完整 Frame，必须切出两条独立消息
func TestReadFrame_Coalesced(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, []byte("second")); err != nil {
		t.Fatal(err)
	}

	scratch := make([]byte, MaxFrameBytes)
	for _, want := range []string{"first", "second"} {
		n, err := ReadFrameHeader(&buf)
		if err != nil {
			t.Fatalf("header: %v", err)
		}
		body, err := ReadFrameBody(&buf, scratch, n)
		if err != nil {
			t.Fatalf("body: %v", err)
		}
		if string(body) != want {
			t.Fatalf("body = %q, want %q", body, want)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("还剩 %d 字节没被消费", buf.Len())
	}
}

// oneByteReader 每次 Read 只返回 1 字节，模拟被拆到极致的半包
type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

// 半包：逐字节喂入，ReadFull 必须把它们攒回完整消息
func TestReadFrame_Fragmented(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 5000)

	var wire bytes.Buffer
	if err := WriteFrame(&wire, payload); err != nil {
		t.Fatal(err)
	}
	r := &oneByteReader{data: wire.Bytes()}

	n, err := ReadFrameHeader(r)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	if n != uint32(len(payload)) {
		t.Fatalf("n = %d, want %d", n, len(payload))
	}
	body, err := ReadFrameBody(r, make([]byte, MaxFrameBytes), n)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("正文内容不一致")
	}
}

// --- 截断 -----------------------------------------------------------------

// 只发长度不发完整正文（slowloris 的静态版本）：必须报错而不是返回短消息。
// 真实连接上由正文 deadline 兜底，这里验证的是不会把半条消息当成完整消息
func TestReadFrameBody_Truncated(t *testing.T) {
	wire := append(hdr(100), bytes.Repeat([]byte("y"), 40)...)
	r := bytes.NewReader(wire)

	n, err := ReadFrameHeader(r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ReadFrameBody(r, make([]byte, MaxFrameBytes), n)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

// 对端在帧边界上正常关闭，必须是干净的 io.EOF —— 调用方据此区分
// 正常断开与协议违规，两者的处理和审计完全不同
func TestReadFrameHeader_CleanEOF(t *testing.T) {
	if _, err := ReadFrameHeader(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

// --- 缓冲区约束 -----------------------------------------------------------

func TestReadFrameBody_BufferTooSmall(t *testing.T) {
	r := bytes.NewReader(bytes.Repeat([]byte("z"), 100))
	if _, err := ReadFrameBody(r, make([]byte, 10), 100); err == nil {
		t.Fatal("want error when buf smaller than n")
	}
}

// --- 写侧 -----------------------------------------------------------------

func TestWriteFrame_RejectsIllegalSizes(t *testing.T) {
	if err := WriteFrame(io.Discard, nil); !errors.Is(err, ErrZeroLength) {
		t.Fatalf("空 payload err = %v, want ErrZeroLength", err)
	}
	oversize := make([]byte, MaxFrameBytes+1)
	if err := WriteFrame(io.Discard, oversize); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("超限 payload err = %v, want ErrFrameTooLarge", err)
	}
}

// 线格式必须是「4 字节大端长度（不含自身）+ 正文」。
// 这条断言的是 wire 兼容性——跨语言 SDK 靠它对齐，不能只测自己读得回来
func TestWriteFrame_WireLayout(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	want := []byte{0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire = % x, want % x", got, want)
	}
}

// failAfterNWrites 在第 N 次 Write 时失败，用于模拟「头写出去了、正文没写成」
type failAfterNWrites struct {
	n   int
	cnt int
}

func (w *failAfterNWrites) Write(p []byte) (int, error) {
	w.cnt++
	if w.cnt > w.n {
		return 0, errors.New("boom")
	}
	return len(p), nil
}

// 正文写失败必须报错，不能静默成功——调用方要据此关闭连接。
// 若吞掉这个错误，对端会永远卡在等待 N 字节正文
func TestWriteFrame_BodyWriteFailure(t *testing.T) {
	if err := WriteFrame(&failAfterNWrites{n: 1}, []byte("abc")); err == nil {
		t.Fatal("正文写失败时必须返回错误")
	}
}
