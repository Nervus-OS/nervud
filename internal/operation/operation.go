// 见 doc.go 的包说明
//
// 本文件是 Operation 的数据模型与状态机：State 枚举、Origin 绑定、Operation 记录、
// 对外事件，以及【唯一】权威的合法转移判定 canTransition。状态机是本包的正确性
// 核心，与并发/装配无关，单独成文件便于单测穷举全部转移（spec §3/§10）。
package operation

import (
	"errors"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/identity"
)

// State 是 Operation 的生命周期状态（NRCP §11.2 / spec §3）
//
// 零值 StateUnspecified 永远不是合法结论：与所有 *_UNSPECIFIED=0 枚举同一个
// 理由，漏填必须 fail-closed，不能因为没赋值就默默落到某个真实状态（铁律 3）。
type State uint8

const (
	// StateUnspecified 是零值哨兵，永不是合法状态
	StateUnspecified State = iota
	StatePending
	StateRunning
	StateCancelRequested
	StateSucceeded
	StateFailed
	StateCancelled
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateRunning:
		return "running"
	case StateCancelRequested:
		return "cancel_requested"
	case StateSucceeded:
		return "succeeded"
	case StateFailed:
		return "failed"
	case StateCancelled:
		return "cancelled"
	default:
		return "unspecified"
	}
}

// Terminal 报告 s 是否为终态。终态之后不接受任何转移（铁律 2）。
func (s State) Terminal() bool {
	return s == StateSucceeded || s == StateFailed || s == StateCancelled
}

// canTransition 是【唯一】权威的合法转移判定（spec §3 的"唯一允许集合"）。
// 其余一律非法，调用方拒绝并记审计。
//
// 唯一允许集合：
//
//	PENDING          → RUNNING | CANCEL_REQUESTED | FAILED
//	RUNNING          → CANCEL_REQUESTED | SUCCEEDED | FAILED
//	CANCEL_REQUESTED → SUCCEEDED | FAILED | CANCELLED
//	（终态无任何出边）
//
// 注意：PENDING → SUCCEEDED 不允许（真实成功必先经 RUNNING）；PENDING →
// CANCELLED 不允许（取消必先经 CANCEL_REQUESTED，spec §3 的权威列表未列出
// PENDING→CANCELLED，尽管状态图的 rejectBeforeStart 支线画到了 CANCELLED——
// 以权威列表为准，reject-before-start 走 PENDING→FAILED）。
func canTransition(from, to State) bool {
	switch from {
	case StatePending:
		return to == StateRunning || to == StateCancelRequested || to == StateFailed
	case StateRunning:
		return to == StateCancelRequested || to == StateSucceeded || to == StateFailed
	case StateCancelRequested:
		return to == StateSucceeded || to == StateFailed || to == StateCancelled
	default:
		// 终态与 Unspecified 没有任何合法出边
		return false
	}
}

// OriginBinding 是 operation 创建时绑定的受信类型信息（NRCP §11.1 / 铁律 6）
//
// 它让 SDK 重连后能恢复解码 typed progress/result/error：detail 的 Protobuf
// 类型由这份绑定决定，【不】使用 google.protobuf.Any 或客户端提供的 type URL。
// Get/事件投影必须返回它。
type OriginBinding struct {
	InterfaceID string
	IfaceMajor  uint32
	IfaceMinor  uint32
	MethodID    uint32
	SchemaHash  []byte // 与 RobotCatalog/endpoint 投影一致
}

// ConnHandle 是拥有本 operation 的 IPC 连接的不透明身份，由 internal/ipc 的
// *conn 满足（照抄 endpoint.ConnHandle 的既有idiom）。
//
// 本包不知道也不需要知道 conn 的具体形状（避免反向依赖 ipc），只要它可比较，
// 供连接断开时按连接收敛未终结 operation（ReleaseByConn）与可见性无关的清理
// 使用。零值 nil = 系统内部创建（无拥有连接）。
type ConnHandle any

// Operation 是一条系统协调长任务的权威记录（spec §4）
//
// v1 内存态，不跨 nervud 重启持久化。终态载荷（TerminalStatus/Result/Error）
// 仅终态非空；其类型由 Origin 绑定决定，不用 Any。
type Operation struct {
	ID          uint64          // nervud 分配，host-session 作用域，单调递增，不复用
	Origin      OriginBinding   // 受信类型绑定
	Caller      identity.Caller // 创建者身份，供可见性裁决与审计归因
	Resources   []string        // 绑定的 resource_handle 集合（v1 通常 {arm.main} 一个）
	LeaseID     uint64          // 关联的 ControlLease（运动类必需；0 = 非运动类，无 lease）
	MotionEpoch uint64          // 创建时的 motion epoch，供 Safety supersede 的陈旧判定
	Deadline    time.Time       // 有限时效；到点未终结 → FAILED(DEADLINE_EXCEEDED)
	State       State

	// 终态载荷（仅终态非空）
	TerminalStatus ipcv1.StatusCode // OK(→SUCCEEDED) / CANCELLED / 其它(→FAILED)
	TerminalResult []byte           // 可选 typed 成功结果（SUCCEEDED）
	TerminalError  []byte           // 可选 typed 错误 detail（FAILED）

	CreatedAt time.Time
	UpdatedAt time.Time

	// conn 是拥有本 operation 的连接，未导出：外部快照看不到它，只用于
	// ReleaseByConn 的按连接收敛。系统内部创建时为 nil。
	conn ConnHandle
}

// clone 返回一份对外安全的深拷贝：切片字段独立，调用方改动不回写内部状态。
func (o *Operation) clone() Operation {
	cp := *o
	cp.Origin.SchemaHash = cloneBytes(o.Origin.SchemaHash)
	cp.Resources = cloneStrings(o.Resources)
	cp.TerminalResult = cloneBytes(o.TerminalResult)
	cp.TerminalError = cloneBytes(o.TerminalError)
	return cp
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return append([]string(nil), s...)
}

// EventKind 区分订阅通道上事件的种类（*_UNSPECIFIED=0 fail-closed）。
type EventKind uint8

const (
	// EventKindUnspecified 是零值哨兵
	EventKindUnspecified EventKind = iota
	// EventProgress 是 typed 进度事件，不改变 state（Provider.Progress）
	EventProgress
	// EventState 是一次状态转移（含终态）
	EventState
)

// Event 是订阅通道上投影给 SDK 的一条事件（spec §5 Subscribe）
//
// 携带 Origin 绑定：SDK 重连后据此恢复解码 typed payload/result/error（铁律 6）。
type Event struct {
	OperationID uint64
	Kind        EventKind
	State       State // 当前状态（EventState 有意义；EventProgress 为转移前状态）
	Origin      OriginBinding
	Payload     []byte // EventProgress 的 typed 进度载荷

	// 终态载荷（仅 EventState 且 State 为终态时非空）
	TerminalStatus ipcv1.StatusCode
	TerminalResult []byte
	TerminalError  []byte
}

// 对外/包内共享的哨兵错误。Provider 回报与内部转移用它们区分失败原因，
// 供审计离线分析与调用方分支。
var (
	// ErrNotFound 该 id 不存在，或跨 caller 访问（可见性不可区分投影，
	// 不泄露他人 operation 的存在，spec §5）。
	ErrNotFound = errors.New("operation: not found")

	// ErrIllegalTransition 请求的状态转移不在唯一允许集合内（记审计后拒绝）。
	ErrIllegalTransition = errors.New("operation: illegal state transition")

	// ErrAlreadyTerminal 目标 operation 已处终态，终态只写一次（幂等/记审计）。
	ErrAlreadyTerminal = errors.New("operation: already in a terminal state")

	// ErrStaleEpoch Provider 上报的 motion epoch 与创建时绑定的不符，
	// 世界已在其下越过一个撤销边界（Safety 触发/lease 变更），fail-closed 拒绝。
	ErrStaleEpoch = errors.New("operation: motion epoch is stale")

	// ErrSuperseded operation 诞生于一条已被 Safety/撤销边界越过的 motion epoch
	// 之前，已被系统接管为 FAILED；Provider 的任何后续推进都被同步拒绝（铁律 1/4）。
	ErrSuperseded = errors.New("operation: superseded by a revocation boundary")

	// ErrDeadlineExceeded operation 的 deadline 已过、已被收敛为 FAILED；
	// Provider 的任何后续推进都被同步拒绝。
	ErrDeadlineExceeded = errors.New("operation: deadline exceeded")

	// ErrProviderContract Provider 违反回报契约（如 Fail 传入只能由 nervud
	// 产生的裁决 code，或未知/越权枚举）。系统 fail-closed 归一化为 INTERNAL
	// 并把它审计为契约违规（铁律 1/3）。
	ErrProviderContract = errors.New("operation: provider contract violation")

	// ErrNotRunning Progress 只能在 RUNNING/CANCEL_REQUESTED 期间上报。
	ErrNotRunning = errors.New("operation: not in a running state")

	// ErrShuttingDown Manager 已停机，不再受理新 operation。
	ErrShuttingDown = errors.New("operation: manager is shutting down")
)
