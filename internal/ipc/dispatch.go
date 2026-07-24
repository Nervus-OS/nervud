// 本文件实现的 route 表:nervud 转发一个 Request 给某个 Service
// 连接时,用 route_id 记录 (源连接、源 request_id、目标连接、deadline),
// 供 DispatchResult 到达、超时清道夫、连接断开三条路径共同消费
//
// 设计核心:谁在表锁下成功删除了这条 entry,谁就是这次调用唯一的终结
// Response 生产者 - 三条路径统一走查表并删除语义,天然保证每个 Request
// 最多一个终结 Response，因此不需要额外的原子完成标记
//
// 已知简化:架构设想的 route 表项还应记录endpoint binding generation用于
// 校验 DispatchResult 是否针对同一次绑定,但 endpoint.RouteInfo 没有暴露这个
// 字段(且 internal/endpoint 不属于本次改动范围)。这里退化为route_id 唯一 +
// DispatchResult 必须来自登记的目标连接本身(指针身份比较)。弱化场景:同一条
// 仍然打开的 Service 连接上,若 Provider 在旧 route 还在途时对同一 interface
// 做了 unregister+重新 register,这里抓不住这次错位 - 范围小,不假装解决
package ipc

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
)

// routeEntry 是一条在途 Dispatch 的相关状态
type routeEntry struct {
	routeID         uint64
	source          *conn
	sourceRequestID uint64
	target          *conn
	deadline        time.Time
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
)

// dispatchTable 是 route_id -> 在途 Dispatch 的唯一权威
type dispatchTable struct {
	mu      sync.Mutex
	entries map[uint64]*routeEntry

	// nextID 从 1 开始,0 视为从未分配,呼应 request_id 的既有约定
	// (route_id 本身的 proto 注释没有明文保留 0,这是本实现引入的惯例)
	nextID atomic.Uint64
}

func newDispatchTable() *dispatchTable {
	return &dispatchTable{entries: make(map[uint64]*routeEntry)}
}

// create 分配一个新 route_id 并登记表项
func (t *dispatchTable) create(source *conn, sourceReqID uint64, target *conn, deadline time.Time) uint64 {
	id := t.nextID.Add(1)
	t.mu.Lock()
	t.entries[id] = &routeEntry{
		routeID:         id,
		source:          source,
		sourceRequestID: sourceReqID,
		target:          target,
		deadline:        deadline,
	}
	t.mu.Unlock()
	return id
}

// complete 尝试完成一个 route,要求结果来自登记的目标连接本身
func (t *dispatchTable) complete(routeID uint64, target *conn) (*routeEntry, completeStatus) {
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
	}
	return e, ok
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
		case e.source:
			asSource = append(asSource, e)
			delete(t.entries, id)
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
		}
	}
	t.mu.Unlock()

	return expired
}

// resolveRoute 是全部完成一个 route路径的共同尾声:归还 source 的 in-flight
// 计数,并把最终 Response 送进 source 的 outbox。返回值转发自 enqueue,只有
// handleRequest 的同步路径关心它(用于决定是否继续读源连接)
func resolveRoute(e *routeEntry, resp *ipcv1.Response) bool {
	e.source.inFlight.Add(-1)
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
		resolveRoute(e, failureResponse(e.sourceRequestID, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE))
	}
	for _, e := range asSource {
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
