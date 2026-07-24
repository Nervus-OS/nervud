// 本文件是 Operation Manager 的本体：kernel.Module 生命周期、对外操作面
// （Create/Get/Cancel/Subscribe）、消费者定义的窄接口（ResourceValidator/
// LeaseValidator）、订阅 fan-out、后台收敛 goroutine，以及无阻塞的 Safety
// 接管投递 SafetySupersede。状态机本身在 operation.go，Provider 回报接缝在
// reporter.go。
package operation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
)

// ResourceValidator 是 resource 侧的窄接口（消费者定义，*resource.Module 隐式
// 满足）。Create 用它校验 resource_handle 是否是当前机器人 Profile 里的已知句柄。
type ResourceValidator interface {
	Valid(handle string) bool
}

// LeaseValidator 是 control 侧的窄接口（消费者定义）。运动类 operation
// （leaseID != 0）在 Create 时用它校验：给定 leaseID 当前是否授权对 resource
// 的运动，且 epoch 新鲜（= 与活跃 motion epoch 一致）。任何存疑一律返回 false
// （fail-closed）。
//
// v1 尚无 operation 的 wire proto，leaseID <-> control 的 lease 句柄（[16]byte +
// ConnID）映射要等 dispatch 接线后提供。因此 main.go 目前注入 fail-closed
// 占位实现，运动类 operation 在 wire 接线前一律被前置拒绝。
type LeaseValidator interface {
	ValidLease(leaseID, epoch uint64, resource string) bool
}

// deadlineScanInterval 是后台 goroutine 扫描 deadline 到期的节拍。operation
// 不是热路径，秒级 deadline 用 100ms 分辨率足够；空闲时一次扫描只遍历少量在跑
// operation，代价可忽略。
const deadlineScanInterval = 100 * time.Millisecond

// subBuffer 是每个订阅通道的缓冲深度。fan-out 用非阻塞发送，满即丢弃（
// 别反压 - 慢消费者不能拖住状态机，更不能拖住 Safety 收敛）。
const subBuffer = 16

// maxDeadlineHorizon 是 Create 允许的最长时效上限。防止一个荒谬的远期 deadline
// 让 operation 实际上永不超时。arm 轨迹/导航都在分钟级以内。
const maxDeadlineHorizon = 30 * time.Minute

// terminalRetention 是终态 operation 在 m.ops 里的保留时长。终态记录不能立即删
// （SDK 重连/晚到的 Get/Subscribe 还要读到结论），但也不能永久累积，否则接上 IPC
// 后就是一条内存 DoS 通道。到期后由后台扫描回收（含其终态载荷）。
const terminalRetention = 5 * time.Minute

// subscription 是一条订阅。closed 标记幂等关闭；所有对 ch 的发送与 close 都在
// Manager.mu 下进行，因此不存在 send-on-closed 竞态。
type subscription struct {
	ch     chan Event
	closed bool
}

// Manager 是 nervud 的 Operation Manager，同时实现 kernel.Module。
//
// 一把 mu 保护 ops 与 subs；v1 数量小，单锁能保持状态转移和订阅发布一致。终态转移是
// mu 下的 compare-and-set - 只有当前非终态且转移合法才写入，并发的
// Succeed/Fail/Cancelled 由 mu 决出唯一胜者。
type Manager struct {
	res   ResourceValidator
	lease LeaseValidator
	aud   audit.Recorder
	log   *slog.Logger

	// now 供测试注入可控时钟；生产恒为 time.Now。
	now func() time.Time

	mu   sync.Mutex
	ops  map[uint64]*Operation
	subs map[uint64][]*subscription

	// nextID 单调递增分配 operation_id，从 1 起（0 为无效哨兵），不复用。
	nextID atomic.Uint64

	// supersedeEpoch 是 Safety 投递来的"接管边界"：所有 MotionEpoch < 它的
	// 在跑运动类 operation 都应被收敛为 FAILED。SafetySupersede 只做一次
	// 原子 max 写 + 一次非阻塞 wake，绝不碰 mu，因此绝不阻塞 Safety Lane
	// 实际收敛在后台 goroutine 里做，避免阻塞 Safety 调用方。
	supersedeEpoch atomic.Uint64

	// wake 唤醒后台 goroutine 立刻做一轮收敛（buffered 1 + 非阻塞发送）。
	wake chan struct{}

	stopCh   chan struct{}
	stopOnce sync.Once
	doneCh   chan struct{} // 后台 goroutine 退出信号
}

// New 构造 Operation Manager。
//
// res/lease 以窄接口注入（main.go 装配）。lease 可为 nil：此时任何运动类
// operation（leaseID != 0）都被前置拒绝（fail-closed）。aud 必须非 nil。
func New(res ResourceValidator, lease LeaseValidator, aud audit.Recorder, log *slog.Logger) *Manager {
	return &Manager{
		res:    res,
		lease:  lease,
		aud:    aud,
		log:    log,
		now:    time.Now,
		ops:    make(map[uint64]*Operation),
		subs:   make(map[uint64][]*subscription),
		wake:   make(chan struct{}, 1),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

func (m *Manager) Name() string { return "operation" }

// Start 起后台收敛 goroutine。它同时负责 deadline 到期扫描与 Safety supersede
// 收敛。循环退出只听 Stop
// 关的 stopCh，不听 Start(ctx) 的 ctx - 否则会与 stopAll 被同一个信号并行唤醒，
// 停机顺序不再由反序 Stop 唯一决定，收尾（收敛未终结 operation、审计）可能被截断。
func (m *Manager) Start(_ context.Context) error {
	go m.loop()
	if m.log != nil {
		m.log.Info("operation: ready")
	}
	return nil
}

// Stop 停掉后台 goroutine，并把未终结 operation 按策略收敛为 FAILED。
// 停机后不留在跑 operation：新 host session 从空开始，与 motion epoch 语义一致。
func (m *Manager) Stop(_ context.Context) error {
	m.stopOnce.Do(func() { close(m.stopCh) })
	<-m.doneCh // 等后台 goroutine 退出，之后独占访问、不与它并发收敛

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range m.ops {
		if op.State.Terminal() {
			continue
		}
		// 停机收敛：未终结 operation 一律 FAILED(UNAVAILABLE)。运动类的相关
		// 控制由 control 在自己的 Stop 里撤租 + 递增 epoch（本包不碰 gate）。
		m.terminateLocked(op, StateFailed, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE, nil,
			actionShutdown, ErrShuttingDown)
	}
	return nil
}

// loop 是唯一的后台 goroutine：deadline 扫描 + Safety supersede 收敛。
// 退出只听 stopCh。
func (m *Manager) loop() {
	defer close(m.doneCh)
	t := time.NewTicker(deadlineScanInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-m.wake:
			m.convergeSupersede()
		case <-t.C:
			m.convergeSupersede()
			m.scanDeadlines()
			m.reapTerminal()
		}
	}
}

// -------------------------------------------------------------------------
// 对外操作面
// -------------------------------------------------------------------------

// Create 创建一个 operation（由 dispatch 在遇到 operation-returning method 时调用）。
//
// 校验：resource 有效（ResourceValidator.Valid）、运动类（leaseID != 0）
// 需有效 ControlLease 且 epoch 新鲜、deadline 合理。成功返回 (id, ACCEPTED)；
// 失败返回 (0, 前置错误码) - 前置失败不签发 id、不落库，只记一条审计
// （等价于状态图的 reject-before-start，但无可追踪句柄，见完成记录）。
//
// conn 是拥有本 operation 的连接，供连接断开时收敛；
// 系统内部创建传 nil。
func (m *Manager) Create(conn ConnHandle, caller identity.Caller, origin OriginBinding,
	resources []string, leaseID, epoch uint64, deadline time.Time) (uint64, ipcv1.StatusCode) {

	if code := m.validateCreate(caller, resources, leaseID, epoch, deadline); code != ipcv1.StatusCode_STATUS_CODE_OK {
		m.recordRejected(caller, resources, leaseID, code)
		return 0, code
	}

	now := m.now()
	id := m.nextID.Add(1)
	// 类型绑定归 Manager 所有：深拷贝 SchemaHash，断开与调用方共享的
	// 底层数组，否则调用方事后改切片就篡改了权威绑定、还会与订阅者读并发成竞态。
	origin.SchemaHash = cloneBytes(origin.SchemaHash)
	op := &Operation{
		ID:          id,
		Origin:      origin,
		Caller:      caller,
		Resources:   cloneStrings(resources),
		LeaseID:     leaseID,
		MotionEpoch: epoch,
		Deadline:    deadline,
		State:       StatePending,
		CreatedAt:   now,
		UpdatedAt:   now,
		conn:        conn,
	}

	m.mu.Lock()
	// 停机后不再受理：否则会签出一条没有后台 goroutine 再去做 deadline/收敛的
	// 孤儿 operation（与 control 停机后拒新签发同理）。
	if m.stopping() {
		m.mu.Unlock()
		m.recordRejected(caller, resources, leaseID, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)
		return 0, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE
	}
	m.ops[id] = op
	// Created 审计在锁内落：解锁后再读 op 会与 Stop/ReleaseByConn/后台收敛并发改
	// op.State 成竞态，还可能把 ShutdownConverged/ConnClosed 记在 Created 之前
	// （顺序倒置）。record 只做一次快速 slog（生产异步），持锁记它与其它转移审计一致。
	m.record(actionCreated, op, false, nil)
	m.mu.Unlock()

	return id, ipcv1.StatusCode_STATUS_CODE_ACCEPTED
}

// validateCreate 跑 Create 的全部前置校验，返回 OK 表示通过。不改任何状态。
func (m *Manager) validateCreate(caller identity.Caller, resources []string,
	leaseID, epoch uint64, deadline time.Time) ipcv1.StatusCode {

	// 必须至少绑定一个 resource；空句柄是畸形请求。
	if len(resources) == 0 {
		return ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
	}
	for _, h := range resources {
		if h == "" {
			return ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
		}
		// 未知/无效 resource 是前置不满足（照抄 control 对 lease 前置失败用
		// FAILED_PRECONDITION 的既有映射）。
		if m.res == nil || !m.res.Valid(h) {
			return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION
		}
	}

	// deadline 合理性：必须在未来，且不荒谬地远。
	now := m.now()
	if !deadline.After(now) || deadline.After(now.Add(maxDeadlineHorizon)) {
		return ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
	}

	// 运动类由 leaseID != 0 数据驱动，必须有有效 lease 和新鲜 epoch，
	// 且绑定到本 operation 的 resource（v1 单 resource）。
	if leaseID != 0 {
		if m.lease == nil {
			return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION
		}
		for _, h := range resources {
			if !m.lease.ValidLease(leaseID, epoch, h) {
				return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION
			}
		}
	}
	_ = caller // caller 已由 dispatch 鉴权；本包仅存它用于可见性与审计
	return ipcv1.StatusCode_STATUS_CODE_OK
}

// Get 快照一个 operation（含 Origin 绑定，供 SDK 重连恢复解码）。
// 只有创建者 caller 或系统可见；跨 caller 返回未命中，避免泄露 operation 是否存在。
func (m *Manager) Get(caller identity.Caller, id uint64) (Operation, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok || !canSee(caller, op) {
		return Operation{}, false
	}
	return op.clone(), true
}

// Cancel 请求取消（ -> CANCEL_REQUESTED）。返回 ACCEPTED != 已取消：
// 它只表示取消请求已受理，真正的 CANCELLED 要等 Provider 确认（reporter.Cancelled）。
//
// 可见性：跨 caller 返回 NOT_FOUND。已终结的 operation：取消是 no-op，仍返回
// ACCEPTED（请求已收到，但状态不会变，符合"ACCEPTED != 已取消"语义）。
func (m *Manager) Cancel(caller identity.Caller, id uint64) ipcv1.StatusCode {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok || !canSee(caller, op) {
		return ipcv1.StatusCode_STATUS_CODE_NOT_FOUND
	}
	switch {
	case op.State.Terminal():
		// 已终结：无可取消，幂等 no-op。
	case op.State == StateCancelRequested:
		// 已在取消中：幂等 no-op。
	case canTransition(op.State, StateCancelRequested):
		m.transitionLocked(op, StateCancelRequested)
		m.record(actionCancelRequested, op, false, nil)
	}
	return ipcv1.StatusCode_STATUS_CODE_ACCEPTED
}

// Subscribe 订阅某 operation 的状态/进度事件。返回 (只读通道, 取消函数)。
//
// 取消函数幂等：调用即从 fan-out 摘除本订阅并关闭通道。连接断开时由 ipc 调它
// 清理，避免订阅泄漏。operation 到终态时通道也会被自动关闭。
// 跨 caller 或不存在：返回一个已关闭的空通道 + no-op 取消函数（不可区分投影）。
func (m *Manager) Subscribe(caller identity.Caller, id uint64) (<-chan Event, func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok || !canSee(caller, op) {
		closed := make(chan Event)
		close(closed)
		return closed, func() {}
	}
	// 若 operation 已终结：没有未来事件可等，直接返回一个已关闭的空通道，不
	// 注册进 m.subs。否则该订阅会一直挂在 fan-out 名单里，只关闭不摘除，调用方若
	// 不再调 cancel 就永久残留 - 接上 IPC 后可被反复 Subscribe 撑成内存 DoS。
	if op.State.Terminal() {
		closed := make(chan Event)
		close(closed)
		return closed, func() {}
	}
	sub := &subscription{ch: make(chan Event, subBuffer)}
	m.subs[id] = append(m.subs[id], sub)
	cancel := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.removeSubLocked(id, sub)
	}
	return sub.ch, cancel
}

// ReleaseByConn 把某条连接名下所有未终结 operation 收敛为 FAILED（运动类的相关
// 控制由 control 侧撤租，本包不碰 gate）。连接断开时由 ipc 调用。
func (m *Manager) ReleaseByConn(conn ConnHandle) {
	if conn == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range m.ops {
		if op.conn != conn || op.State.Terminal() {
			continue
		}
		m.terminateLocked(op, StateFailed, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE, nil,
			actionConnClosed, errConnClosed)
	}
}

// -------------------------------------------------------------------------
// Safety 接管
// -------------------------------------------------------------------------

// SafetySupersede 由 control/safety 侧在 Safety 触发时调用：把该 epoch 之前所有
// 在跑的运动类 operation 标记为 FAILED（被接管）。
//
// 绝不阻塞 Safety Lane：本函数只做一次原子 max 写 + 一次非阻塞 wake 投递即
// 返回，不取 mu、不做 fan-out、不做任何可能阻塞的操作。真正的状态收敛在后台
// goroutine 的 convergeSupersede 里做（用 mu + 非阻塞 fan-out）。因此即便存在
// 会阻塞的慢订阅者，Safety 路径也不被拖住。
//
// epoch 是 Safety 递增之后的新 motion epoch：MotionEpoch < epoch 的运动类
// operation 都诞生于这条撤销边界之前，一律被接管。
func (m *Manager) SafetySupersede(epoch uint64) {
	// 原子 max：多次触发只抬高边界，不会被晚到的旧值倒写回去。
	for {
		cur := m.supersedeEpoch.Load()
		if epoch <= cur {
			break
		}
		if m.supersedeEpoch.CompareAndSwap(cur, epoch) {
			break
		}
	}
	// 非阻塞 wake：满了（已有待处理）就跳过，后台 goroutine 会读到最新边界。
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// convergeSupersede 把 MotionEpoch < supersedeEpoch 的在跑运动类 operation 收敛为
// FAILED。在后台 goroutine 里跑，可以安全地取 mu 与做 fan-out - 它不在 Safety 路径上。
func (m *Manager) convergeSupersede() {
	boundary := m.supersedeEpoch.Load()
	if boundary == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range m.ops {
		if op.State.Terminal() {
			continue
		}
		// 只接管运动类（有 lease）且诞生于边界之前的 operation。非运动类
		// （leaseID==0）不受物理 Safety 边界影响，不在此收敛（见完成记录）。
		if op.LeaseID == 0 || op.MotionEpoch >= boundary {
			continue
		}
		m.terminateLocked(op, StateFailed, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION, nil,
			actionSafetySuperseded, ErrSuperseded)
	}
}

// scanDeadlines 把已过 deadline 的未终结 operation 收敛为 FAILED(DEADLINE_EXCEEDED)。
func (m *Manager) scanDeadlines() {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range m.ops {
		if op.State.Terminal() || op.Deadline.IsZero() || !now.After(op.Deadline) {
			continue
		}
		m.terminateLocked(op, StateFailed, ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED, nil,
			actionDeadlineExceeded, ErrDeadlineExceeded)
	}
}

// reapTerminal 回收超过 terminalRetention 的终态 operation，界定内存占用（防 DoS）。
// 终态的订阅已在 terminateLocked 里关闭并从 m.subs 摘除；这里再 defensively 清一次。
func (m *Manager) reapTerminal() {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, op := range m.ops {
		if op.State.Terminal() && now.Sub(op.UpdatedAt) > terminalRetention {
			delete(m.ops, id)
			delete(m.subs, id)
		}
	}
}

// -------------------------------------------------------------------------
// 内部：转移、终态写入、订阅 fan-out、审计（均要求持有 mu）
// -------------------------------------------------------------------------

// transitionLocked 应用一次非终态转移并 fan-out EventState。调用方须已确认
// canTransition。终态转移走 terminateLocked（带载荷 + CAS 语义）。
func (m *Manager) transitionLocked(op *Operation, to State) {
	op.State = to
	op.UpdatedAt = m.now()
	m.emitLocked(op, Event{
		OperationID: op.ID,
		Kind:        EventState,
		State:       to,
		Origin:      op.Origin,
	})
}

// terminateLocked 是终态写入的唯一入口，compare-and-set 语义：只有当前
// 非终态且转移合法才写入。它设置终态载荷、fan-out 终态事件、关闭并摘除全部订阅、
// 记审计。已是终态或转移非法时是安全 no-op（幂等），不覆盖既有终态。
func (m *Manager) terminateLocked(op *Operation, to State, status ipcv1.StatusCode,
	detail []byte, action string, cause error) bool {

	if op.State.Terminal() || !canTransition(op.State, to) {
		return false
	}
	op.State = to
	op.UpdatedAt = m.now()
	op.TerminalStatus = status
	// 终态载荷归 Manager 所有：深拷贝，断开与 Provider 调用方共享的
	// 底层数组，写入后不可被外部改动。
	switch to {
	case StateSucceeded:
		op.TerminalResult = cloneBytes(detail)
	case StateFailed:
		op.TerminalError = cloneBytes(detail)
	}
	m.emitLocked(op, Event{
		OperationID:    op.ID,
		Kind:           EventState,
		State:          to,
		Origin:         op.Origin,
		TerminalStatus: status,
		TerminalResult: op.TerminalResult,
		TerminalError:  op.TerminalError,
	})
	m.closeAllSubsLocked(op.ID)
	m.record(action, op, cause != nil, cause)
	return true
}

// emitLocked 把一条事件非阻塞 fan-out 给该 operation 的全部订阅者。通道满即丢弃
// （不反压，慢消费者可随时 Get 补齐）。
//
// 事件里的 byte 切片先深拷贝一份再投递：让订阅者拿到的副本与权威记录的
// SchemaHash/result/error 底层数组不共享 - 某个订阅者若违约改动切片，只会
// 弄坏它自己那份，不会篡改记录或与记录的读并发成竞态。同一批订阅者共享
// 这一份副本，Event 对接收方按只读约定使用。
func (m *Manager) emitLocked(op *Operation, ev Event) {
	subs := m.subs[op.ID]
	if len(subs) == 0 {
		return
	}
	ev.Origin.SchemaHash = cloneBytes(ev.Origin.SchemaHash)
	ev.Payload = cloneBytes(ev.Payload)
	ev.TerminalResult = cloneBytes(ev.TerminalResult)
	ev.TerminalError = cloneBytes(ev.TerminalError)
	for _, sub := range subs {
		if sub.closed {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
			// 丢弃：订阅通道满，慢消费者不能拖住状态机/Safety 收敛。
		}
	}
}

// closeAllSubsLocked 关闭并摘除该 operation 的全部订阅（终态后无未来事件）。
func (m *Manager) closeAllSubsLocked(id uint64) {
	for _, sub := range m.subs[id] {
		if !sub.closed {
			sub.closed = true
			close(sub.ch)
		}
	}
	delete(m.subs, id)
}

// removeSubLocked 从 fan-out 名单摘除并关闭一个订阅（Subscribe 返回的取消函数）。
func (m *Manager) removeSubLocked(id uint64, target *subscription) {
	subs := m.subs[id]
	for i, sub := range subs {
		if sub != target {
			continue
		}
		if !sub.closed {
			sub.closed = true
			close(sub.ch)
		}
		m.subs[id] = append(subs[:i], subs[i+1:]...)
		if len(m.subs[id]) == 0 {
			delete(m.subs, id)
		}
		return
	}
}

// stopping 报告 Manager 是否已进入停机（stopCh 已关）。要求持有 mu 或在 Create
// 的临界区内调用，以与 ops 写入保持一致视图。
func (m *Manager) stopping() bool {
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

// canSee 报告 caller 是否可见 op：系统（空 PackageID = kernel）或创建者本人。
// 跨 caller 一律不可见，避免泄露他人的 operation 是否存在。
func canSee(caller identity.Caller, op *Operation) bool {
	if caller.PackageID == "" {
		return true // 系统/内核
	}
	return caller.PackageID == op.Caller.PackageID
}

// -------------------------------------------------------------------------
// 审计
// -------------------------------------------------------------------------

// 审计 Action 名。离线规则按 "operation.<Action>" 匹配。
const (
	actionCreated          = "Created"
	actionCreateRejected   = "CreateRejected"
	actionCancelRequested  = "CancelRequested"
	actionAccepted         = "Accepted"
	actionSucceeded        = "Succeeded"
	actionFailed           = "Failed"
	actionCancelled        = "Cancelled"
	actionIllegal          = "IllegalTransition"
	actionSafetySuperseded = "SafetySuperseded"
	actionDeadlineExceeded = "DeadlineExceeded"
	actionConnClosed       = "ConnClosed"
	actionShutdown         = "ShutdownConverged"
)

// 系统内部收敛用的哨兵原因（写进审计 Err，供离线分析区分非正常终结）。
// Safety 接管/deadline 过期复用对外哨兵 ErrSuperseded/ErrDeadlineExceeded
// （见 operation.go），审计与 Provider 返回同源，避免同一概念两个 error。
var errConnClosed = errStr("owning connection closed")

// errStr 是最小的 error，用于系统内部收敛原因。用值类型避免包级可变 error 触发
// gochecknoglobals 之外的顾虑，同时让审计 Err 字段有稳定文本。
type errStr string

func (e errStr) Error() string { return string(e) }

// record 落一条与具体 operation 相关的审计。denied 用于让离线规则筛出非正常终结。
func (m *Manager) record(action string, op *Operation, denied bool, cause error) {
	m.aud.Record(context.Background(), audit.Event{
		Action:  "operation." + action,
		Subject: op.Caller.String(),
		Denied:  denied,
		Err:     cause,
		Detail: fmt.Sprintf("op=%d state=%s iface=%s method=%d lease=%d epoch=%d",
			op.ID, op.State, op.Origin.InterfaceID, op.Origin.MethodID, op.LeaseID, op.MotionEpoch),
	})
}

// recordRejected 记一条 Create 前置拒绝。此时还没有 operation 记录，归因用申请方身份。
func (m *Manager) recordRejected(caller identity.Caller, resources []string, leaseID uint64, code ipcv1.StatusCode) {
	m.aud.Record(context.Background(), audit.Event{
		Action:  "operation." + actionCreateRejected,
		Subject: caller.String(),
		Denied:  true,
		Err:     fmt.Errorf("create rejected: code=%d", int32(code)),
		Detail:  fmt.Sprintf("resources=%v lease=%d", resources, leaseID),
	})
}
