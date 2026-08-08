// 本文件是审计记录的哈希链: 让局部篡改留下痕迹.
//
// # 它防的是什么, 不防什么
//
// 防: 删掉中间几条, 改一条的 subject, 把两条对调顺序, 把某条的
// denied=true 改成 false. 任何一处改动都会让它之后的每一条 prev 对不上,
// 而重算需要把后面全部重写.
//
// 不防: 有 root 权限的人把整个文件重写一遍并重算全链. 那需要外部锚点
//
//	(远程日志, TPM, 一次性写入介质) 才谈得上 - 本文件不假装能做到.
//
// 目标是篡改可见而不是篡改不可能: 绝大多数情况下, 审计被改动是误操作,
// 日志轮转脚本写错, 或者一次没想清楚的"清理一下", 而不是有预谋的攻击.
// 那些情形本文件全都能暴露.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// chainVersion 进每一条记录.
//
// 必须在链里: 校验工具要能分辨"这条记录我算不出来"与"这条记录被改过".
// 少了版本号, 一次格式演进会让全部历史记录看起来像被篡改.
const chainVersion = 1

// Record 是落盘的一条审计, JSON Lines 的一行.
//
// 字段顺序即 JSON 键顺序 (encoding/json 按结构体字段序输出), 而哈希算的是
// 序列化之后的字节 - 所以字段顺序是链的一部分, 重排会让历史记录全部失效.
type Record struct {
	// V 是链格式版本.
	V int `json:"v"`

	// Seq 从 1 起, 单调递增, 不复用. 0 是"无前驱"的哨兵.
	Seq uint64 `json:"seq"`

	// Prev 是前一条记录的 Hash (十六进制). 链首为空字符串.
	Prev string `json:"prev"`

	// TimeUnixNanos 是落盘时刻 (墙钟).
	//
	// 墙钟而不是单调时钟: 审计要回答"几点发生的", 那必须能与外部事件
	//  (工单, 监控告警, 现场记录) 对上. 单调时钟对不上任何东西.
	//
	// 代价是墙钟可以被调整, 因此它不参与任何裁决, 只供人阅读与关联.
	TimeUnixNanos int64 `json:"t"`

	Action  string `json:"action"`
	Subject string `json:"subject"`
	Denied  bool   `json:"denied"`
	Err     string `json:"err,omitempty"`
	Detail  string `json:"detail,omitempty"`

	// Hash 是本条记录 (不含本字段) 的 SHA-256, 十六进制.
	Hash string `json:"hash"`
}

// hashInput 是参与哈希的那一份, 即除 Hash 之外的全部字段.
//
// 单独定义而不是把 Record 的 Hash 置空再序列化: 置空的做法依赖
// `json:"hash,omitempty"`, 而一旦有人去掉那个 omitempty, 全部历史记录会在
// 同一刻失效, 且没有任何编译错误.
type hashInput struct {
	V             int    `json:"v"`
	Seq           uint64 `json:"seq"`
	Prev          string `json:"prev"`
	TimeUnixNanos int64  `json:"t"`
	Action        string `json:"action"`
	Subject       string `json:"subject"`
	Denied        bool   `json:"denied"`
	Err           string `json:"err,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// newRecord 用给定的前驱链接一条新记录并算好哈希.
func newRecord(seq uint64, prev string, at time.Time, ev Event) (Record, error) {
	rec := Record{
		V:             chainVersion,
		Seq:           seq,
		Prev:          prev,
		TimeUnixNanos: at.UnixNano(),
		Action:        ev.Action,
		Subject:       ev.Subject,
		Denied:        ev.Denied,
		Detail:        ev.Detail,
	}
	if ev.Err != nil {
		rec.Err = ev.Err.Error()
	}
	sum, err := rec.computeHash()
	if err != nil {
		return Record{}, err
	}
	rec.Hash = sum
	return rec, nil
}

func (r Record) computeHash() (string, error) {
	wire, err := json.Marshal(hashInput{
		V:             r.V,
		Seq:           r.Seq,
		Prev:          r.Prev,
		TimeUnixNanos: r.TimeUnixNanos,
		Action:        r.Action,
		Subject:       r.Subject,
		Denied:        r.Denied,
		Err:           r.Err,
		Detail:        r.Detail,
	})
	if err != nil {
		return "", fmt.Errorf("audit: encode record for hashing: %w", err)
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyChain 校验一段连续记录. 返回第一条出问题的下标与原因.
//
// expectedPrev 是这一段之前那条记录的 Hash; 一个文件从头校验时传空字符串.
// expectedSeq 同理, 从头校验传 1.
//
// 逐条报位置而不是只说"链坏了": 审计出问题时最要紧的是"从哪一条开始
// 不对" - 那基本就指出了事件发生的时间窗.
func VerifyChain(records []Record, expectedPrev string, expectedSeq uint64) (int, error) {
	prev := expectedPrev
	seq := expectedSeq

	for i, rec := range records {
		if rec.V != chainVersion {
			return i, fmt.Errorf("audit: record %d has chain version %d, this build understands %d",
				rec.Seq, rec.V, chainVersion)
		}
		if rec.Seq != seq {
			// 序号跳跃 = 有记录被删掉, 或者被插入.
			return i, fmt.Errorf("audit: record seq %d, want %d (records removed or inserted)",
				rec.Seq, seq)
		}
		if rec.Prev != prev {
			return i, fmt.Errorf("audit: record %d has prev %q, want %q (chain broken)",
				rec.Seq, rec.Prev, prev)
		}
		want, err := rec.computeHash()
		if err != nil {
			return i, err
		}
		if want != rec.Hash {
			// 内容被改过: 字段变了但 hash 没跟着重算.
			return i, fmt.Errorf("audit: record %d hash mismatch (content modified)", rec.Seq)
		}
		prev = rec.Hash
		seq++
	}
	return -1, nil
}
