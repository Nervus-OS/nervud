// Package subscription 实现事件订阅与扇出.
//
// # 三条连接的关系
//
//	订阅方 -> nervud: Subscribe(40) 建立 (endpoint, event_id) 订阅
//	Provider -> nervud: PublishEvent(53) 上报一条事件
//	nervud -> 订阅方: Event(43) 扇出, 各自携带 subscription_id 与 sequence
//
// 投递决策留在 nervud, 不在 Provider. Provider 不知道有哪些订阅者, 也不该
// 知道 - 订阅方的权限可能在订阅之后被撤销, Provider 无从得知. 它只说"这个
// endpoint 上发生了这个事件", 由谁收得到是内核的事.
//
// # 背压落在 nervud 与订阅方之间
//
// PublishEvent 是单向的, 没有结果. 给它配一个结果会让 Provider 的事件循环变成
// 请求-响应, 一个慢订阅者就能拖住整个 Provider. 正确的落点是每个订阅方各自的
// 出站队列: 慢的那个按自己的 delivery_class 被合并, 被丢弃或被断开, 不影响别人.
package subscription

import (
	"sync"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

// Sink 是一条订阅方连接的出站口. ipc.conn 隐式满足.
//
// Deliver 返回 false 表示队列已满 (慢消费者). Registry 据此按 delivery_class
// 决定合并, 丢弃还是关闭订阅.
type Sink interface {
	Deliver(env *ipcv1.Envelope) bool
}

// Key 唯一标识一个事件源: Provider 连接上的某个 endpoint 的某个事件,
// 外加一个可选的实例作用域.
//
// 用 Provider 侧的 (连接, endpoint_id) 而不是接口名: 同一个接口可以有多个
// Provider, 订阅方订的是它解析到的那一个, 不是"所有实现了这个接口的".
type Key struct {
	ProviderConn any
	EndpointID   uint64
	EventID      uint32

	// Scope 把一个 endpoint 上的多个可独立观察的实例分开. 0 = 不分.
	//
	// # 它解决的问题
	//
	// 一个内建 endpoint 上跑着全机的 operation, 一路摄像头上开着好几条 stream.
	// 没有 Scope 的话, 订阅方会收到全部实例的事件 - 那不只是浪费带宽,
	// 是信息泄漏: 别人的进度, 失败细因, 资源句柄都会送到.
	//
	// # 为什么是 uint64 而不是 any
	//
	// 现实里的实例标识全是数字句柄 (operation_id, stream_id), 而 any 作为
	// map 键会在运行时因为不可比较的动态类型 panic - 那种 panic 发生在扇出
	// 热路径上, 会带走整个 nervud.
	//
	// # 精确匹配, 没有通配
	//
	// Scope 不同即收不到. 想"订阅全部"就是回到广播, 而广播正是本字段要
	// 解决的问题. 需要整机视角的运维工具走管理通道, 不走 App 控制面.
	Scope uint64
}

// subscription 是一条已建立的订阅.
type subscription struct {
	id       uint64
	sink     Sink
	conn     any // 订阅方连接, 用于按连接批量清理
	key      Key
	meta     *ipcv1.EventMeta
	sequence uint64
	// dropped 是自上一条已投递事件以来被合并或丢弃的条数.
	// 投递成功后清零 - 它描述的是"这条与上一条之间发生了什么".
	dropped uint64
	// callerEndpointID 是订阅方自己看到的 endpoint 句柄. Event.endpoint_id 用它,
	// 而不是 Provider 侧的 - 两者是不同命名空间的数字, 混用会让订阅方
	// 路由到一个它从没见过的 endpoint.
	callerEndpointID uint64
}

// Registry 持有全部订阅.
//
// 两张索引指向同一批 subscription: byKey 用于扇出 (热路径), byConn 用于连接
// 断开时批量清理. 任何增删都必须两边同时改, 否则会留下收不到事件的幽灵订阅,
// 或者向已关闭的连接投递.
type Registry struct {
	mu     sync.RWMutex
	byKey  map[Key][]*subscription
	byConn map[any]map[uint64]*subscription
	// nextID 按订阅方连接分配, 永不复用 (见 Subscribe 的注释).
	nextID map[any]uint64
}

func New() *Registry {
	return &Registry{
		byKey:  make(map[Key][]*subscription),
		byConn: make(map[any]map[uint64]*subscription),
		nextID: make(map[any]uint64),
	}
}

// Subscribe 登记一条订阅并返回连接作用域的 subscription_id.
//
// 句柄永不复用: 复用会让退订后到达的在途 Event 被错认成新订阅的数据,
// 而这种错认在遥测/状态流里几乎无法被察觉 - 数字对得上, 连接也对得上,
// 接收方没有任何办法分辨. 与 endpoint_id, lease 句柄同一条理由.
func (r *Registry) Subscribe(
	callerConn any, sink Sink, callerEndpointID uint64, key Key, meta *ipcv1.EventMeta,
) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nextID[callerConn]++
	id := r.nextID[callerConn]

	s := &subscription{
		id: id, sink: sink, conn: callerConn, key: key, meta: meta,
		callerEndpointID: callerEndpointID,
	}
	r.byKey[key] = append(r.byKey[key], s)
	if r.byConn[callerConn] == nil {
		r.byConn[callerConn] = make(map[uint64]*subscription)
	}
	r.byConn[callerConn][id] = s
	return id
}

// Unsubscribe 撤下一条订阅. 返回是否确实存在.
func (r *Registry) Unsubscribe(callerConn any, id uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	subs := r.byConn[callerConn]
	s, ok := subs[id]
	if !ok {
		return false
	}
	delete(subs, id)
	if len(subs) == 0 {
		delete(r.byConn, callerConn)
	}
	r.removeFromKeyLocked(s)
	return true
}

func (r *Registry) removeFromKeyLocked(s *subscription) {
	list := r.byKey[s.key]
	for i, candidate := range list {
		if candidate != s {
			continue
		}
		list = append(list[:i], list[i+1:]...)
		break
	}
	if len(list) == 0 {
		delete(r.byKey, s.key)
		return
	}
	r.byKey[s.key] = list
}

// DeliveryClassOf 给出一个事件的生效投递类别.
//
// 未指定 fail closed 为 RELIABLE. RELIABLE 是最严的一档 (不允许任何丢弃).
// 把一个漏填当成"可以随便丢"才是危险的默认: 客户端会以为自己拿到了完整序列.
func DeliveryClassOf(meta *ipcv1.EventMeta) ipcv1.DeliveryClass {
	switch c := meta.GetDeliveryClass(); c {
	case ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE,
		ipcv1.DeliveryClass_DELIVERY_CLASS_STATE,
		ipcv1.DeliveryClass_DELIVERY_CLASS_LOSSY:
		return c
	default:
		return ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE
	}
}

// Closed 是一条因背压被终止的订阅, 调用方据此发 SubscriptionClosed 并清理.
type Closed struct {
	Conn           any
	SubscriptionID uint64
	Reason         ipcv1.SubscriptionClosedReason
}

// Publish 把一条事件扇出给 key 上的全部订阅者.
//
// 返回需要被关闭的订阅 (RELIABLE 类别下投递不下的那些). 调用方负责发出
// SubscriptionClosed 并调 Unsubscribe - 本函数不直接碰订阅方的连接生命周期.
//
// 每个订阅者各自计 sequence: sequence 是"本订阅内的第几条", 不是全局序号.
// 用全局序号的话, 一个中途加入的订阅方会看到从一个巨大数字开始的序列,
// 而它无从判断前面那些是"没订上"还是"丢了".
func (r *Registry) Publish(key Key, payload []byte, timestampNanos uint64) []Closed {
	r.mu.Lock()
	defer r.mu.Unlock()

	var closed []Closed
	for _, s := range r.byKey[key] {
		class := DeliveryClassOf(s.meta)
		s.sequence++
		env := &ipcv1.Envelope{Body: &ipcv1.Envelope_Event{Event: &ipcv1.Event{
			SubscriptionId:          s.id,
			Sequence:                s.sequence,
			EndpointId:              s.callerEndpointID,
			EventId:                 key.EventID,
			Payload:                 payload,
			Dropped:                 s.dropped,
			MonotonicTimestampNanos: timestampNanos,
		}}}

		if s.sink.Deliver(env) {
			s.dropped = 0
			continue
		}

		// 投递不下. 三种类别的正确反应完全不同
		switch class {
		case ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE:
			// 不得静默丢弃. 只能终止这一条订阅 - 而不是关掉整条连接:
			// 同一个订阅方可能还有别的, 消费得动的订阅
			closed = append(closed, Closed{
				Conn: s.conn, SubscriptionID: s.id,
				Reason: ipcv1.SubscriptionClosedReason_SUBSCRIPTION_CLOSED_REASON_BACKPRESSURE,
			})
		case ipcv1.DeliveryClass_DELIVERY_CLASS_STATE,
			ipcv1.DeliveryClass_DELIVERY_CLASS_LOSSY:
			// 这一条没送出去, 记进 dropped 让下一条带上.
			// sequence 已经递增过, 因此订阅方看到的缺口与 dropped 对得上
			s.dropped++
		}
	}
	return closed
}

// CloseConn 清掉一条连接名下的全部订阅, 返回被清掉的 id.
//
// 订阅方断开时调用. 不需要发 SubscriptionClosed - 对端已经没了.
func (r *Registry) CloseConn(callerConn any) []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	subs := r.byConn[callerConn]
	if len(subs) == 0 {
		delete(r.nextID, callerConn)
		return nil
	}
	ids := make([]uint64, 0, len(subs))
	for id, s := range subs {
		ids = append(ids, id)
		r.removeFromKeyLocked(s)
	}
	delete(r.byConn, callerConn)
	// nextID 一并删除: 连接没了, 它的句柄空间也就没了. 留着只会白占内存,
	// 而下一条连接是新的 map 键, 从 1 重新开始 - 不同连接的相同数字本就
	// 不是同一个东西 (查找键是 (连接, 句柄)).
	delete(r.nextID, callerConn)
	return ids
}

// CloseScope 终止指向某个实例的全部订阅.
//
// 实例消失时调用 - 一个 operation 走到终态并被回收之后, 再也不会有它的事件.
// 不关同一 endpoint 上别的实例: 那些还活着.
//
// 与 CloseProviderEndpoint 的关系是包含: 那个关整个 endpoint (endpoint 本身
// 失效了), 这个只关一个实例. 用错的后果方向相反 - 用前者会误杀别人的订阅,
// 用后者会漏掉本该关的.
func (r *Registry) CloseScope(
	providerConn any, endpointID, scope uint64, reason ipcv1.SubscriptionClosedReason,
) []Closed {
	r.mu.Lock()
	defer r.mu.Unlock()

	var closed []Closed
	for key, list := range r.byKey {
		if key.ProviderConn != providerConn || key.EndpointID != endpointID ||
			key.Scope != scope {
			continue
		}
		for _, s := range list {
			closed = append(closed, Closed{
				Conn: s.conn, SubscriptionID: s.id, Reason: reason,
			})
			if subs := r.byConn[s.conn]; subs != nil {
				delete(subs, s.id)
				if len(subs) == 0 {
					delete(r.byConn, s.conn)
				}
			}
		}
		delete(r.byKey, key)
	}
	return closed
}

// CloseProviderEndpoint 终止指向某个 Provider endpoint 的全部订阅.
//
// endpoint 失效或被撤权时调用: 那之后再也不会有事件, 让订阅方一直等着比
// 明确告诉它更糟. 跨全部实例作用域 - endpoint 都没了, 它上面的实例
// 自然也没了.
func (r *Registry) CloseProviderEndpoint(
	providerConn any, endpointID uint64, reason ipcv1.SubscriptionClosedReason,
) []Closed {
	r.mu.Lock()
	defer r.mu.Unlock()

	var closed []Closed
	for key, list := range r.byKey {
		if key.ProviderConn != providerConn || key.EndpointID != endpointID {
			continue
		}
		for _, s := range list {
			closed = append(closed, Closed{
				Conn: s.conn, SubscriptionID: s.id, Reason: reason,
			})
			if subs := r.byConn[s.conn]; subs != nil {
				delete(subs, s.id)
				if len(subs) == 0 {
					delete(r.byConn, s.conn)
				}
			}
		}
		delete(r.byKey, key)
	}
	return closed
}

// Len 返回当前订阅总数, 供诊断与测试.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, subs := range r.byConn {
		n += len(subs)
	}
	return n
}
