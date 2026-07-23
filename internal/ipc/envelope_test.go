package ipc

import (
	"errors"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
	"google.golang.org/protobuf/proto"
)

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestParseEnvelope_RoundTrip(t *testing.T) {
	in := &ipcv1.Envelope{
		Body: &ipcv1.Envelope_Ping{Ping: &ipcv1.Ping{Nonce: 42}},
	}
	env, err := parseEnvelope(mustMarshal(t, in))
	if err != nil {
		t.Fatalf("parseEnvelope: %v", err)
	}
	if got := env.GetPing().GetNonce(); got != 42 {
		t.Fatalf("nonce = %d, want 42", got)
	}
}

func TestParseEnvelope_MalformedIsViolation(t *testing.T) {
	// 0x08 是 field 1 varint 的 tag，后面缺少 varint 正文 —— 截断的 wire 数据
	_, err := parseEnvelope([]byte{0x08})
	if !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("err = %v, want ErrMalformedEnvelope", err)
	}
	if !isProtocolViolation(err) {
		t.Fatal("畸形 Envelope 必须被判定为协议违规")
	}
}

// 空 Envelope 没有合法用途：容忍它等于给「刷空帧消耗预算」留口子
func TestParseEnvelope_EmptyBodyIsViolation(t *testing.T) {
	// 完全空的字节串是合法 Protobuf，但 body 未设置
	_, err := parseEnvelope(nil)
	if !errors.Is(err, ErrEmptyEnvelopeBody) {
		t.Fatalf("err = %v, want ErrEmptyEnvelopeBody", err)
	}
	if !isProtocolViolation(err) {
		t.Fatal("空 body 必须被判定为协议违规")
	}
}

// 只设了版本号、没设 body —— 同样是空 body
func TestParseEnvelope_VersionOnlyIsViolation(t *testing.T) {
	in := &ipcv1.Envelope{ProtocolMajor: 1, ProtocolMinor: 0}
	if _, err := parseEnvelope(mustMarshal(t, in)); !errors.Is(err, ErrEmptyEnvelopeBody) {
		t.Fatalf("err = %v, want ErrEmptyEnvelopeBody", err)
	}
}

// 未知【字段】必须被忽略而不是报错（架构 10.12：旧接收方可以忽略未知字段）。
// 这与未知 body 的处理刻意相反，两条一起测才能锁住这个区别
func TestParseEnvelope_UnknownFieldIsTolerated(t *testing.T) {
	in := &ipcv1.Envelope{Body: &ipcv1.Envelope_Ping{Ping: &ipcv1.Ping{Nonce: 7}}}
	b := mustMarshal(t, in)

	// 追加一个本 schema 里不存在的字段：field 999，varint 类型
	// tag = 999<<3 | 0 = 7992 -> varint 编码
	b = append(b, 0xC0, 0x3E, 0x01)

	env, err := parseEnvelope(b)
	if err != nil {
		t.Fatalf("未知字段不该导致解析失败: %v", err)
	}
	if got := env.GetPing().GetNonce(); got != 7 {
		t.Fatalf("nonce = %d, want 7（未知字段不应破坏已知字段）", got)
	}
}

// 未知 body（来自更新版本的对端）会落进 unknown fields，Body 保持 nil，
// 因此按违规处理 —— 继续处理一个本端根本不实现的语义只会产生未定义行为
func TestParseEnvelope_UnknownBodyIsViolation(t *testing.T) {
	// field 199 是 Envelope oneof 里未分配的号，长度分隔类型
	// tag = 199<<3 | 2 = 1594 -> varint 编码 0xBA 0x0C，随后长度 0
	b := []byte{0xBA, 0x0C, 0x00}
	if _, err := parseEnvelope(b); !errors.Is(err, ErrEmptyEnvelopeBody) {
		t.Fatalf("err = %v, want ErrEmptyEnvelopeBody", err)
	}
}
