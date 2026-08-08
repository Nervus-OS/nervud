// 本文件是事件实例归属表: 谁有资格订阅一个 endpoint 上的哪一个实例.
//
// # 它填的缺口
//
// 订阅是按 (endpoint, event_id) 建的. 一路摄像头上可以同时开好几条 stream,
// 不分实例就意味着订了 cam.front 的 A 会收到 B 那条 stream 的状态变化 -
// 什么时候开的, 开了多久, 什么时候掉的线.
//
// 而"这条 stream 是不是你开的"只有 Provider 知道. 本表就是它把这个知识
// 交给 nervud 的地方.
//
// # 为什么是预先登记, 而不是订阅时问 Provider
//
// 问一次要一次往返, 而 Subscribe 跑在连接的读循环里: 等待期间这条连接上的
// 请求响应, Ping, 乃至别的订阅全都读不到. 一个慢 Provider 能拖住整条连接.
//
// 预先登记把这次往返挪到了创建实例的那一刻 - 那里本来就在处理一次调用,
// 多带一句话不增加任何等待.
//
// # 归属靠 route 证明, 不靠自报
//
// Provider 说的是"这个 scope 属于我正在处理的这次调用的调用方", 而那次调用
// 是谁发起的, nervud 自己知道 (route -> source conn). 与 BeginTransfer 用
// origin_route_id 证明身份是同一个套路.
package ipc

import "sync"

// scopeKey 唯一标识一个事件实例.
//
// 用 Provider 侧的 (连接, endpoint_id): 与订阅扇出的键同源, 两者对不上就会
// 出现"登记了但订不上"或者反过来.
type scopeKey struct {
	providerConn *conn
	endpointID   uint64
	scope        uint64
}

// eventScopes 记录实例归属.
//
// BindEventScope 与 Subscribe 分别来自不同连接的读循环 goroutine,
// 因此必须加锁.
type eventScopes struct {
	mu sync.Mutex
	// owner 是有资格订阅该实例的连接.
	owner map[scopeKey]*conn
	// byProvider / byOwner 是两张反向索引, 供断开时批量清理.
	//
	// 两张都要: Provider 死了, 它登记的实例全都不再存在; 调用方死了,
	// 它的实例也随之消失 (stream 绑在连接上). 少任何一张, 对应那种断开就会
	// 留下永远清不掉的条目.
	byProvider map[*conn]map[scopeKey]struct{}
	byOwner    map[*conn]map[scopeKey]struct{}
}

func newEventScopes() *eventScopes {
	return &eventScopes{
		owner:      make(map[scopeKey]*conn),
		byProvider: make(map[*conn]map[scopeKey]struct{}),
		byOwner:    make(map[*conn]map[scopeKey]struct{}),
	}
}

// bind 登记一次归属. 重复登记同一个 key 会覆盖.
//
// 覆盖而不是拒绝: Provider 复用一个 scope 号是它自己的事 (关掉再开同一条
// 流), 拒绝会让它不得不先撤销再登记, 而中间那一小段里订阅会失败. 覆盖的语义
// 是"这个 scope 现在属于这一位", 与最新的事实一致.
func (s *eventScopes) bind(provider *conn, endpointID, scope uint64, owner *conn) {
	key := scopeKey{providerConn: provider, endpointID: endpointID, scope: scope}

	s.mu.Lock()
	defer s.mu.Unlock()

	if previous, exists := s.owner[key]; exists && previous != owner {
		s.detachOwnerLocked(previous, key)
	}
	s.owner[key] = owner
	addScopeIndex(s.byProvider, provider, key)
	addScopeIndex(s.byOwner, owner, key)
}

// release 撤销一次登记.
func (s *eventScopes) release(provider *conn, endpointID, scope uint64) {
	key := scopeKey{providerConn: provider, endpointID: endpointID, scope: scope}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(key)
}

// allows 报告 subscriber 是否有资格订阅这个实例.
//
// 未登记即拒绝. fail closed 的方向在这里格外要紧: 放行一个没登记的 scope
// 等于回到不分实例的广播, 而那正是本表要解决的问题.
func (s *eventScopes) allows(provider *conn, endpointID, scope uint64, subscriber *conn) bool {
	if provider == nil || subscriber == nil || scope == 0 {
		return false
	}
	key := scopeKey{providerConn: provider, endpointID: endpointID, scope: scope}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owner[key] == subscriber
}

// closeProvider 清掉一条 Provider 连接名下的全部登记.
func (s *eventScopes) closeProvider(provider *conn) {
	s.closeIndex(s.byProvider, provider)
}

// closeOwner 清掉一条订阅方连接名下的全部登记.
func (s *eventScopes) closeOwner(owner *conn) {
	s.closeIndex(s.byOwner, owner)
}

// closeEndpoint 清掉一个 Provider endpoint 上的全部登记.
//
// endpoint 撤下时调用: 那之后它上面的实例都不再存在. 不能只等连接断开 -
// 一个长驻 Provider 反复注册撤销 endpoint 会让登记无界累积.
func (s *eventScopes) closeEndpoint(provider *conn, endpointID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.byProvider[provider] {
		if key.endpointID == endpointID {
			s.removeLocked(key)
		}
	}
}

func (s *eventScopes) closeIndex(index map[*conn]map[scopeKey]struct{}, c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 先取快照: removeLocked 会改这张索引, 边遍历边删是未定义行为.
	keys := make([]scopeKey, 0, len(index[c]))
	for key := range index[c] {
		keys = append(keys, key)
	}
	for _, key := range keys {
		s.removeLocked(key)
	}
}

// removeLocked 摘掉一条登记及它在两张索引里的痕迹.
func (s *eventScopes) removeLocked(key scopeKey) {
	owner, exists := s.owner[key]
	if !exists {
		return
	}
	delete(s.owner, key)
	s.detachOwnerLocked(owner, key)
	if set := s.byProvider[key.providerConn]; set != nil {
		delete(set, key)
		if len(set) == 0 {
			delete(s.byProvider, key.providerConn)
		}
	}
}

func (s *eventScopes) detachOwnerLocked(owner *conn, key scopeKey) {
	set := s.byOwner[owner]
	if set == nil {
		return
	}
	delete(set, key)
	if len(set) == 0 {
		delete(s.byOwner, owner)
	}
}

func addScopeIndex(index map[*conn]map[scopeKey]struct{}, c *conn, key scopeKey) {
	set := index[c]
	if set == nil {
		set = make(map[scopeKey]struct{})
		index[c] = set
	}
	set[key] = struct{}{}
}

// len 供诊断与测试.
func (s *eventScopes) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.owner)
}
