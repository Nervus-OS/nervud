// 本文件是分帧层与协议语义层之间的交接：把一帧字节解成 Envelope，并做
// Protobuf 本身表达不了的良构校验
//
// 连接状态机（Hello/HelloAck 协商、body 分派）见 conn.go（待落地）。这里只回答
// 「这帧到底算不算一个合法的 Envelope」，不回答「此刻允不允许收到这种 body」
package ipc

import (
	"errors"
	"fmt"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
	"google.golang.org/protobuf/proto"
)

// 这两个同样是协议违规：出现即关闭连接，不生成 Response
//
// 与 frame.go 的长度错误同级——那边是「边界不可信」，这边是「边界可信但内容
// 不是一个 Envelope」。两种情况下继续对话都没有意义
var (
	ErrMalformedEnvelope = errors.New("ipc: malformed envelope")
	ErrEmptyEnvelopeBody = errors.New("ipc: envelope body is not set")
)

// parseEnvelope 把一帧正文解成 Envelope
//
// 解码前不做任何业务判断，解码后只做两条与状态无关的校验：
//
//  1. 必须是合法 Protobuf。畸形输入直接断开而不是回错误码——能构造畸形帧的
//     对端不会因为收到一条 INVALID_ARGUMENT 就改邪归正，回复只是白送带宽
//  2. body 必须已设置。空 Envelope 没有任何合法用途，容忍它等于给「刷空帧
//     消耗预算」留口子；来自未知新版本的未知 body 也会落到这里（proto3 把
//     不认识的 oneof 分支收进 unknown fields，Body 保持 nil），同样按违规处理
//
// 未知【字段】与未知【body】的处理刻意不同：前者被 proto 运行时保留并忽略，
// 满足架构 10.12 的「旧接收方可以忽略未知字段」；后者意味着对端在用本端根本
// 不实现的语义，继续处理只会产生未定义行为
func parseEnvelope(b []byte) (*ipcv1.Envelope, error) {
	var env ipcv1.Envelope
	if err := proto.Unmarshal(b, &env); err != nil {
		// 不把 proto 的原始错误文本外泄给对端，只在本端日志/审计里留全文
		return nil, fmt.Errorf("%w: %v", ErrMalformedEnvelope, err)
	}
	if env.GetBody() == nil {
		return nil, ErrEmptyEnvelopeBody
	}
	return &env, nil
}

// isProtocolViolation 判定一个错误是否属于「这条连接已经没法继续」
//
// 集中在一处判断，避免各调用点各写一套 errors.Is 链——漏掉一种就会把一次
// 协议违规当成普通断开，审计里也就看不见它
func isProtocolViolation(err error) bool {
	return errors.Is(err, ErrZeroLength) ||
		errors.Is(err, ErrFrameTooLarge) ||
		errors.Is(err, ErrMalformedEnvelope) ||
		errors.Is(err, ErrEmptyEnvelopeBody)
}
