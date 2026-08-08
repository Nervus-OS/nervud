// 本文件只保留共用类型和最小 slog 实现, 让安全敏感模块记录审计时不必依赖
// 文件后端或具体持久化策略.
package audit

import (
	"context"
	"log/slog"
)

// Event 是一条安全/权限审计记录
//
// 字段固定, 无 any. 否则无法离线做结构化分析
//
// 本类型被 authority / permission / safety 等多个模块共用, 因此单独定义在 audit 包
type Event struct {
	Action  string // 操作码的字符串形式, 如 "CreatePrivateDataDirectory"
	Subject string // 发起者, 如 "pkg:com.example.app uid:20001"; "kernel" = 内核自身
	Denied  bool   // true = 被策略或不变量拦下, 操作未执行
	Err     error  // nil 表示成功; Denied 时为拒绝原因
	Detail  string // 补充信息 (如目标路径). 禁止写入密钥或口令
}

// Recorder 是审计的写入接口. 使用方持有本接口而非具体实现
type Recorder interface {
	Record(ctx context.Context, ev Event)
}

// New 返回只写 slog 的最小实现.
//
// 生产用 NewFileRecorder: 审计与普通日志混在一起会被日志级别过滤掉,
// 会被轮转策略覆盖, 也没有任何东西能证明它没被改过. file.go 那一份补齐了
// 这三件事, 并且仍然照写 slog.
//
// 本实现留给测试与不需要留证的最小装配.
func New(log *slog.Logger) Recorder { return &slogRecorder{log: log} }

type slogRecorder struct{ log *slog.Logger }

// Record 落一条审计. 固定 Info 级别: 审计不是调试信息
// 不接受被日志级别调低而丢失
func (r *slogRecorder) Record(ctx context.Context, ev Event) {
	r.log.LogAttrs(ctx, slog.LevelInfo, "audit",
		slog.String("action", ev.Action),
		slog.String("subject", ev.Subject),
		slog.Bool("denied", ev.Denied),
		slog.Any("err", ev.Err),
		slog.String("detail", ev.Detail),
	)
}
