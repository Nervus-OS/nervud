// 见 doc.go 的包说明
//
// 本文件是本包全部拒绝原因的集中定义。用哨兵错误（errors.Is 可判定）而不是自由文本：
// 上层要按原因决定回哪个 StatusCode 与哪条 typed error_detail，字符串匹配做不到这件事
package control

import "errors"

// 到 NRCP §19 的映射（位置 A 是 Envelope 的通用 StatusCode，位置 B 是 typed detail）：
//
//	ErrControlNotHeld    FAILED_PRECONDITION + CONTROL_NOT_HELD
//	ErrLeaseExpired      FAILED_PRECONDITION + CONTROL_NOT_HELD  （对调用者同义：你现在没有控制权）
//	ErrDeadmanExpired    FAILED_PRECONDITION + CONTROL_NOT_HELD
//	ErrHeldByHuman       FAILED_PRECONDITION + RESOURCE_BUSY
//	ErrHeldByAI          FAILED_PRECONDITION + RESOURCE_BUSY
//	ErrSafetyLatched     FAILED_PRECONDITION + SAFETY_LATCHED
//	ErrStaleEpoch        FAILED_PRECONDITION + STALE_EPOCH
//	ErrUnknownResource   NOT_FOUND           + RESOURCE_NOT_FOUND
//	ErrInvalidRequest    INVALID_ARGUMENT    （申请本身不良构，与当前状态无关）
//	ErrPolicyViolation   INVALID_ARGUMENT    （申请的 TTL/deadman 超出系统上限）
//
// ErrHeldByHuman 与 ErrHeldByAI 刻意分开而不是合成一个 BUSY：Agent 需要知道「现在是
// 人在遥控」才能去问用户「要我接手吗」——让出的决定权在人，而笼统的 BUSY 表达不了
// 这件事。上层向普通调用者投影时两者都落到 RESOURCE_BUSY，区别只在内核侧与审计里
var (
	// ErrControlNotHeld 没有有效租约，或该租约不属于这个 (ID, ConnID)
	ErrControlNotHeld = errors.New("control: no valid lease held by caller")

	// ErrLeaseExpired 租约 deadline 已过。正常情况下 Control Lane 会先一步收掉它，
	// 本错误覆盖的是「到期与调用同时发生」的窗口
	ErrLeaseExpired = errors.New("control: lease deadline expired")

	// ErrDeadmanExpired 命令新鲜度失效：超过 deadman 窗口没有新鲜输入
	ErrDeadmanExpired = errors.New("control: deadman expired")

	// ErrHeldByHuman 目标 Resource 当前被 HUMAN 持有，且申请者无权抢占
	ErrHeldByHuman = errors.New("control: resource held by HUMAN")

	// ErrHeldByAI 目标 Resource 当前被 AI 持有，且申请者无权抢占（同为 AI）
	ErrHeldByAI = errors.New("control: resource held by AI")

	// ErrSafetyLatched Safety Gate 非 NORMAL。锁存期间不签发任何普通租约，
	// 也不放行任何运动——恢复必须走 OEM Recovery / re-arm，不能靠重新申请控制权
	ErrSafetyLatched = errors.New("control: safety gate is latched")

	// ErrStaleEpoch 租约所属的 motion epoch 已被撤销
	ErrStaleEpoch = errors.New("control: lease belongs to a revoked motion epoch")

	// ErrUnknownResource 申请的 Resource 不是 [REWRITE-v1] 唯一合法的 base.main
	ErrUnknownResource = errors.New("control: unknown resource scope")

	// ErrInvalidRequest 申请本身不良构：Class 未指定、ConnID 为 0 等
	ErrInvalidRequest = errors.New("control: malformed lease request")

	// ErrPolicyViolation 申请的 TTL/deadman 超出 Policy 允许的上限
	//
	// 超限即拒绝而【不是】静默压到上限：静默压短会让调用方以为自己有 5 秒、实际只有
	// 2 秒，于是续租发得太晚，租约在运动中途失效——这比直接拒绝危险得多
	ErrPolicyViolation = errors.New("control: requested lease exceeds policy limits")

	// ErrShuttingDown 模块已进入停机：Stop 已被调用，Control Lane 正在或已经退出。
	// 停机后不再签发任何新租约——否则会签出一条没有 Lane 再去做到期清槽/epoch 撤销的
	// 「孤儿租约」，它能一直通过 Check 授权运动直到进程真正退出（Stop 不是终态的后果）。
	// 它同时用作停机撤租的审计原因。
	ErrShuttingDown = errors.New("control: module shutting down")
)

// 以下哨兵不面向调用者，只作为审计记录里的撤销原因，让离线规则能把
// 「正常释放」与「被动失去控制权」区分开
var (
	errConnectionClosed = errors.New("control: owner connection closed")
	errSafetyRevoked    = errors.New("control: revoked by safety trip")

	// errPackageRevoked 是 RevokeByPackage 撤租时写进审计的原因：包被卸载，或其
	// motion 组权限被用户撤销（应用层架构决策 §6.4）。与 errConnectionClosed 分开，
	// 让离线规则能把「连接断开被动失去控制权」与「因包生命周期/权限变更被撤租」区分开
	errPackageRevoked = errors.New("control: revoked by package lifecycle or permission change")
)
