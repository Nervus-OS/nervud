// 本文件是 Gate 与四步流水线 do() 的实现；请求类型见 request.go
// 平台实现见 ops_linux.go / ops_other.go
package authority

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nervus-os/nervud/internal/audit"
)

// Gate 是 NSOS 全部 Linux 特权操作的唯一入口
//
// 它是 代码架构与审计边界，不是进程级隔离空间
// nervud 一旦被完全执行劫持，应视为整个 NSOS 内核失守
// Gate 的价值在于让特权操作可枚举、可审计、可评审
// 而不在于挡住已经拿到执行权的攻击者
//
// Gate 是 设施 而非 kernel.Module：它没有需要启停的后台循环
// 由 assemble()直接构造，并注入给各模块，生命周期与进程一致
// 注入时按消费者需要给 窄接口，不要把 Gate 整个传下去
type Gate struct {
	auditor audit.Recorder
	inv     *Invariants
	log     *slog.Logger
}

type Config struct {
	Auditor    audit.Recorder
	Invariants *Invariants // nil 则用 DefaultInvariants()
	Log        *slog.Logger
}

// New 构造 Gate
// 主意：不允许缺 Auditor
func New(cfg Config) (*Gate, error) {
	if cfg.Auditor == nil {
		return nil, fmt.Errorf("authority: Auditor is required")
	}
	if cfg.Log == nil {
		return nil, fmt.Errorf("authority: Log is required")
	}
	inv := cfg.Invariants
	if inv == nil {
		inv = DefaultInvariants()
	}
	return &Gate{auditor: cfg.Auditor, inv: inv, log: cfg.Log}, nil
}

// 实现方法
//
//	模块提出请求 -> Authority 检查底层不变量 -> 执行 -> Audit 记录
//
// V2-TODO：Policy 裁决步骤
// 本路径的调用者全部是内核模块，同属一个 TCB、同等可信
// 任何现实威胁，真正跨信任边界的是 App 请求
// 由 internal/permission 的 capability 执法负责，不走这里
// Policy 的真实客户是 scheduler（RT 优先级授予）与 safety（收紧 OEM Safety Contract，NRCP）
//
// 全部导出操作都必须经由本函数：“查了不变量、写了审计”由结构保证，而不是靠开发者自觉
// 泛型仅为消除逐操作的重复流水线；Res 为无返回值的操作时取 struct{
//
// run 是包内不可导出的平台实现，不接受外部注入
func do[Req Request, Res any](
	ctx context.Context,
	g *Gate,
	subj Subject,
	req Req,
	run func(context.Context, Req) (Res, error),
) (Res, error) {
	var zero Res
	kind := req.Kind()
	detail := ""
	if d, ok := any(req).(interface{ Detail() string }); ok {
		detail = d.Detail()
	}

	// Policy 接缝：将来若确有 subject 相关的可变裁决要落在特权路径上，插在这里
	// （Subject 已贯穿全部签名与审计，届时只加判定、不动接口），拒绝用 ErrPolicyDenied

	// 不变量：与调用者无关的系统硬约束，任何策略都不得豁免
	if err := req.Validate(g.inv); err != nil {
		g.auditor.Record(ctx, audit.Event{
			Action: kind.String(), Subject: subj.String(), Denied: true, Err: err, Detail: detail,
		})
		return zero, err
	}

	// 执行真实 Linux 操作（仅本包与 scheduler 可直接触碰 syscall / x/sys / os/exec）
	res, err := run(ctx, req)

	// 审计：成功与失败都记。只记成功的审计日志毫无取证价值
	g.auditor.Record(ctx, audit.Event{
		Action: kind.String(), Subject: subj.String(), Denied: false, Err: err, Detail: detail,
	})
	if err != nil {
		g.log.Error("authority: operation failed",
			"kind", kind.String(), "subject", subj.String(), "err", err)
		return zero, fmt.Errorf("authority: %s: %w", kind, err)
	}
	return res, nil
}
