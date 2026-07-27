// 本文件实现 route 表：nervud 转发一个 Request 给某个 Service 连接时，用
// route_id 记录源/目标连接、请求与方法的权威快照、deadline、registration
// generation 以及 Transfer RouteToken，供正常结果、撤权、超时和断线共同消费。
//
// 设计核心:谁在表锁下成功删除了这条 entry,谁就是这次调用唯一的终结
// Response 生产者 - 三条路径统一走查表并删除语义,天然保证每个 Request
// 最多一个终结 Response，因此不需要额外的原子完成标记
//
// 撤权与发布共用表锁和 epoch：请求在查 endpoint/catalog 前采样 epoch，只有在
// 发布 route 时 epoch 仍相同才成功。撤权先递增 epoch，再摘表并关闭 RouteToken，
// 因而查表与发布之间发生的撤权不会留下一个可在事后 BeginTransfer 的旧 route。
package ipc

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/transfer"
)

// routeEntry 是一条在途 Dispatch 的相关状态
type routeEntry struct {
	routeID         uint64
	source          *conn
	sourceRequestID uint64
	target          *conn
	deadline        time.Time
	methodID        uint32
	route           endpoint.RouteInfo
	execution       *ipcv1.ExecutionContext
	token           *transfer.RouteToken
}

// completeStatus 是 dispatchTable.complete 的结果分类
type completeStatus int

const (
	// completeOK: 找到且 target 匹配,表项已被删除,调用方是唯一的完成者
	completeOK completeStatus = iota
	// completeNotFound: route_id 不存在 - 良性竞态(已被清道夫/另一次结果/
	// 连接断开清理抢先完成),或本来就是伪造的 route_id,二者在这里无法区分
	completeNotFound
	// completeMismatch: route_id 存在,但送回结果的连接不是登记的目标连接。
	// 没有合法解释 - 没有 Service 会被告知一个指向别的连接的 route_id
	completeMismatch
	// completeExpired: target matched, but the result arrived after the exact
	// route deadline. The entry is removed and must resolve as DEADLINE_EXCEEDED.
	completeExpired
)

// dispatchTable 是 route_id -> 在途 Dispatch 的唯一权威
type dispatchTable struct {
	mu      sync.Mutex
	entries map[uint64]*routeEntry
	// epoch changes at every authorization revocation. Request routing samples
	// it before consulting endpoint/catalog state and must present the same
	// value when publishing a route, closing the lookup-to-publish race.
	epoch uint64

	// beforePublishEnqueue is only populated by package tests to pause the
	// publish critical section at the former revoke-before-Dispatch race.
	beforePublishEnqueue func()

	// nextID 从 1 开始,0 视为从未分配,呼应 request_id 的既有约定
	// (route_id 本身的 proto 注释没有明文保留 0,这是本实现引入的惯例)
	nextID atomic.Uint64
	// nextCommandSequence is global within this kernel boot. A global sequence
	// is also strictly monotonic for every resource/generation subsequence while
	// avoiding an unbounded map of retired catalog generations.
	nextCommandSequence uint64
}

type dispatchPublishStatus uint8

const (
	dispatchPublishOK dispatchPublishStatus = iota
	dispatchPublishEpochChanged
	dispatchPublishTargetUnavailable
	dispatchPublishSequenceExhausted
)

func newDispatchTable() *dispatchTable {
	return &dispatchTable{entries: make(map[uint64]*routeEntry)}
}

// create 分配一个新 route_id 并登记表项
func (t *dispatchTable) create(
	source *conn,
	sourceReqID uint64,
	target *conn,
	deadline time.Time,
	route endpoint.RouteInfo,
	methodID uint32,
) uint64 {
	epoch := t.snapshotEpoch()
	id, _ := t.createAtEpoch(
		epoch, source, sourceReqID, target, deadline, route, methodID)
	return id
}

// createAtEpoch publishes a route only if no authorization revocation raced
// with the endpoint/catalog checks that preceded it.
func (t *dispatchTable) createAtEpoch(
	expectedEpoch uint64,
	source *conn,
	sourceReqID uint64,
	target *conn,
	deadline time.Time,
	route endpoint.RouteInfo,
	methodID uint32,
) (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.epoch != expectedEpoch {
		return 0, false
	}
	id := t.nextID.Add(1)
	t.entries[id] = &routeEntry{
		routeID:         id,
		source:          source,
		sourceRequestID: sourceReqID,
		target:          target,
		deadline:        deadline,
		methodID:        methodID,
		route:           route,
		token:           transfer.NewRouteToken(),
	}
	return id, true
}

// publishDispatchAtEpoch atomically publishes route authority and appends the
// corresponding Dispatch to the Provider's in-memory outbox. revoke uses the
// same table lock, so the Provider can observe only one of these orderings:
//
//   - Dispatch is queued first, then a matching CancelDispatch; or
//   - revocation advances epoch first and no Dispatch is queued.
//
// target.outbox.push is non-blocking and performs no socket I/O. Slow-consumer
// teardown is deliberately left to the caller after this lock is released.
func (t *dispatchTable) publishDispatchAtEpoch(
	expectedEpoch uint64,
	source *conn,
	sourceReqID uint64,
	target *conn,
	deadline time.Time,
	route endpoint.RouteInfo,
	methodID uint32,
	remainingMS uint32,
	payload []byte,
	caller *ipcv1.CallerContext,
	execution *ipcv1.ExecutionContext,
) (uint64, dispatchPublishStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.epoch != expectedEpoch {
		return 0, dispatchPublishEpochChanged
	}

	var executionSnapshot *ipcv1.ExecutionContext
	if execution != nil {
		executionSnapshot = &ipcv1.ExecutionContext{
			LeaseId:            execution.GetLeaseId(),
			ControllerClass:    execution.GetControllerClass(),
			MotionEpoch:        execution.GetMotionEpoch(),
			DeadlineNanos:      execution.GetDeadlineNanos(),
			ResourceHandle:     execution.GetResourceHandle(),
			ResourceGeneration: execution.GetResourceGeneration(),
		}
		if executionSnapshot.GetLeaseId() != 0 {
			if t.nextCommandSequence == ^uint64(0) {
				return 0, dispatchPublishSequenceExhausted
			}
			t.nextCommandSequence++
			executionSnapshot.CommandSequence = t.nextCommandSequence
		}
	}

	id := t.nextID.Add(1)
	entry := &routeEntry{
		routeID:         id,
		source:          source,
		sourceRequestID: sourceReqID,
		target:          target,
		deadline:        deadline,
		methodID:        methodID,
		route:           route,
		execution:       executionSnapshot,
		token:           transfer.NewRouteToken(),
	}
	t.entries[id] = entry
	if t.beforePublishEnqueue != nil {
		t.beforePublishEnqueue()
	}
	if target == nil || target.outbox == nil || !target.outbox.push(&ipcv1.Envelope{
		Body: &ipcv1.Envelope_Dispatch{Dispatch: &ipcv1.Dispatch{
			RouteId:          id,
			EndpointId:       route.ServiceEndpointID,
			MethodId:         methodID,
			RemainingMs:      remainingMS,
			Payload:          payload,
			Caller:           caller,
			ExecutionContext: executionSnapshot,
		}},
	}) {
		delete(t.entries, id)
		entry.token.Close()
		return id, dispatchPublishTargetUnavailable
	}
	return id, dispatchPublishOK
}

func (t *dispatchTable) snapshotEpoch() uint64 {
	t.mu.Lock()
	epoch := t.epoch
	t.mu.Unlock()
	return epoch
}

// revoke closes matching route tokens under the same lock that publishes
// routes. Incrementing epoch even when no entry matches rejects a Route lookup
// that started before this revocation but has not published yet.
func (t *dispatchTable) revoke(match func(*routeEntry) bool) []*routeEntry {
	t.mu.Lock()
	t.epoch++
	var revoked []*routeEntry
	for id, entry := range t.entries {
		if !match(entry) {
			continue
		}
		delete(t.entries, id)
		entry.token.Close()
		revoked = append(revoked, entry)
	}
	t.mu.Unlock()
	return revoked
}

func (t *dispatchTable) revokeEndpoint(
	provider *conn,
	endpointID, generation uint64,
) []*routeEntry {
	return t.revoke(func(entry *routeEntry) bool {
		return entry.target == provider &&
			entry.route.ServiceEndpointID == endpointID &&
			(generation == 0 || entry.route.RegistrationGeneration == generation)
	})
}

func (t *dispatchTable) revokePackage(packageID string) []*routeEntry {
	return t.revoke(func(entry *routeEntry) bool {
		return entry.source.caller.PackageID == packageID ||
			entry.target.caller.PackageID == packageID
	})
}

func (t *dispatchTable) revokePermission(packageID, permission string) []*routeEntry {
	return t.revoke(func(entry *routeEntry) bool {
		return entry.source.caller.PackageID == packageID &&
			slices.Contains(entry.route.RequiredPermissions, permission)
	})
}

func (t *dispatchTable) revokeResource(resource string, generation uint64) []*routeEntry {
	return t.revoke(func(entry *routeEntry) bool {
		return entry.route.ResourceHandle == resource &&
			entry.route.ResourceGeneration == generation
	})
}

func (t *dispatchTable) revokeControl(
	caller transfer.ConnID,
	resource string,
) []*routeEntry {
	return t.revoke(func(entry *routeEntry) bool {
		return transfer.ConnID(entry.source.connID) == caller &&
			entry.route.ResourceHandle == resource &&
			methodRequiresControl(entry.route.Method.Meta)
	})
}

// complete 尝试完成一个 route,要求结果来自登记的目标连接本身
func (t *dispatchTable) complete(
	routeID uint64,
	target *conn,
	nowValues ...time.Time,
) (*routeEntry, completeStatus) {
	now := time.Now()
	if len(nowValues) != 0 {
		now = nowValues[0]
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[routeID]
	if !ok {
		return nil, completeNotFound
	}
	if e.target != target {
		return nil, completeMismatch
	}
	delete(t.entries, routeID)
	e.token.Close()
	if !now.Before(e.deadline) {
		return e, completeExpired
	}
	return e, completeOK
}

// completeAny 无条件完成一个 route(不校验来源),供清道夫与
// handleRequest 自己的刚创建就发现目标连接已经废了路径使用 - 两者都已经
// 通过别的渠道确认这条 route 该结束,不需要再核对是谁在结束它
func (t *dispatchTable) completeAny(routeID uint64) (*routeEntry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[routeID]
	if ok {
		delete(t.entries, routeID)
		e.token.Close()
	}
	return e, ok
}

// origin returns the immutable authorization snapshot for a live route only
// when the querying connection is that route's Provider target. The route
// token closes the race with completion immediately after this lookup.
func (t *dispatchTable) origin(routeID uint64, target *conn) (*routeEntry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[routeID]
	if !ok || e.target != target || !e.token.Open() {
		return nil, false
	}
	return e, true
}

// connClosed 摘除全部以 c 为 target 或 source 的表项,分类返回供调用方在释放
// 表锁之后处理 - 表锁只保护这张 map 本身,不覆盖把结果送进另一条连接的
// outbox这类连接 I/O( 明确禁止跨连接 I/O 时持锁)
func (t *dispatchTable) connClosed(c *conn) (asTarget, asSource []*routeEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for id, e := range t.entries {
		switch c {
		case e.target:
			asTarget = append(asTarget, e)
			delete(t.entries, id)
			e.token.Close()
		case e.source:
			asSource = append(asSource, e)
			delete(t.entries, id)
			e.token.Close()
		}
	}
	return asTarget, asSource
}

// reap 摘除全部已过期(deadline 已过)的表项,供清道夫周期性调用
func (t *dispatchTable) reap(now time.Time) []*routeEntry {
	var expired []*routeEntry

	t.mu.Lock()
	for id, e := range t.entries {
		if now.After(e.deadline) {
			expired = append(expired, e)
			delete(t.entries, id)
			e.token.Close()
		}
	}
	t.mu.Unlock()

	return expired
}

// resolveRoute 是全部完成一个 route路径的共同尾声:归还 source 的 in-flight
// 计数,并把最终 Response 送进 source 的 outbox。返回值转发自 enqueue,只有
// handleRequest 的同步路径关心它(用于决定是否继续读源连接)
func resolveRoute(e *routeEntry, resp *ipcv1.Response) bool {
	e.source.releaseRequest(e.sourceRequestID)
	return e.source.enqueue(responseEnvelope(resp))
}

// dispatchConnClosed 处理某连接断开对 route 表的影响:
//   - 该连接是某些 route 的 target:调用方等着的是它,不能拖到超时才发现 -
//     立刻合成 UNAVAILABLE 送回各自的 source
//   - 该连接是某些 route 的 source:没有归宿可言,直接丢弃(不产生 Response,
//     没有连接会去读它),并尽力通知对应 target 停止在途工作,避免一个已经
//     没人等待结果的动作继续占着执行器/资源
func (s *Server) dispatchConnClosed(c *conn) {
	asTarget, asSource := s.dispatch.connClosed(c)

	for _, e := range asTarget {
		s.transfer.CloseRoute(e.routeID)
		resolveRoute(e, failureResponse(e.sourceRequestID, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE))
	}
	for _, e := range asSource {
		s.transfer.CloseRoute(e.routeID)
		e.source.releaseRequest(e.sourceRequestID)
		if e.target != nil {
			e.target.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_CancelDispatch{
				CancelDispatch: &ipcv1.CancelDispatch{
					RouteId: e.routeID,
					Reason:  ipcv1.CancelDispatchReason_CANCEL_DISPATCH_REASON_CLIENT_GONE,
				},
			}})
		}
	}
}

// dispatchReapInterval 是清道夫的扫描周期。粗粒度的权衡:一个请求最多会在
// 真正 deadline 之后再晚一个周期才被清理,换来的是表锁的争用频率保持很低。
// 相对于 defaultMethodTimeoutMs=5000/maxMethodTimeoutMs=30000 这两个量级,
// 250ms 的延迟可以忽略
const dispatchReapInterval = 250 * time.Millisecond

// runDispatchReaper 周期性清理超过 deadline 仍未完成的 route,防止一个从不
// 回应的 Service 让调用者的请求永久挂起。生命周期与 acceptLoop 同构:用
// s.wg/s.quit 加入既有的启停协议,不新造机制
func (s *Server) runDispatchReaper() {
	defer s.wg.Done()

	ticker := time.NewTicker(dispatchReapInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.quit:
			return
		case now := <-ticker.C:
			for _, e := range s.dispatch.reap(now) {
				s.transfer.CloseRoute(e.routeID)
				resolveRoute(e, failureResponse(e.sourceRequestID, ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED))
				if e.target != nil {
					e.target.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_CancelDispatch{
						CancelDispatch: &ipcv1.CancelDispatch{
							RouteId: e.routeID,
							Reason:  ipcv1.CancelDispatchReason_CANCEL_DISPATCH_REASON_DEADLINE_EXCEEDED,
						},
					}})
				}
			}
		}
	}
}

// auditDispatchRace 记一条迟到/未知 route_id 的 DispatchResult 被丢弃审计,
// 用独立于 violationLog 的限速桶 - 这是预期内的正常竞态(清道夫或另一次结果
// 抢先完成),不该跟真正的协议违规信号抢占同一份审计预算
func (s *Server) auditDispatchRace(subject string, routeID uint64) {
	if !s.dispatchRaceLog.allow() {
		return
	}
	s.auditor.Record(context.Background(), audit.Event{
		Action:  "ipc.DispatchResultUnmatched",
		Subject: subject,
		Detail:  fmt.Sprintf("route_id=%d", routeID),
	})
}
