package endpoint

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/catalog"
)

// EventRoute 是一次订阅准入的结果。
//
// 与 RouteInfo 的区别在于目标：调用要转发给 Provider，订阅只是【登记】——
// 因此这里给出的是「事件源的坐标」，供 subscription.Registry 建索引。
type EventRoute struct {
	// ProviderConn / ProviderEndpointID 是事件源坐标。Provider 上报
	// PublishEvent 时用的是它自己的 endpoint_id，两者必须能对上。
	ProviderConn       ConnHandle
	ProviderEndpointID uint64

	InterfaceID    string
	InterfaceMajor uint32

	// Event 携带权威 EventMeta：投递类别、速率上限、权限。
	Event catalog.EventDefinition

	// Admit 非 nil 时，本次订阅必须先经它裁决实例作用域（见
	// BuiltinSubscribeAdmitter）。只有内建 endpoint 会给出它。
	Admit BuiltinSubscribeAdmitter
}

// RouteEvent 校验一次订阅并给出事件源坐标。
//
// 准入链与 Route（方法调用）完全同源，逐条复用同一批不变量：binding 仍活着、
// 世代未漂移、资源仍匹配、接口级权限通过。差别只在最后一步查的是事件而非方法。
//
// 【订阅时查一次权限不等于永远有权】：订阅方的授权可能在订阅之后被撤销。
// 那条路径由 permission 的 revoker 触发 CloseProviderEndpoint 一类的清理，
// 不在本函数职责内——这里只保证「建立的那一刻是合法的」。
func (m *Module) RouteEvent(
	conn ConnHandle,
	endpointID uint64,
	eventID uint32,
) (EventRoute, RouteError) {
	if m == nil {
		return EventRoute{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	snapshot := m.snapshot()
	if snapshot == nil {
		return EventRoute{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cs, ok := m.byConn[conn]
	if !ok {
		return EventRoute{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	b, ok := cs.bindings[endpointID]
	if !ok || b.target == nil || !b.target.live ||
		b.targetGeneration != b.target.generation {
		return EventRoute{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	def, provider, valid := registrationInSnapshot(snapshot, b.target)
	if !valid ||
		def.DefinitionGeneration != b.definitionGeneration ||
		provider.DefinitionGeneration != b.providerGeneration ||
		b.interfaceID != b.target.interfaceID ||
		b.interfaceMajor != b.target.ifaceMajor {
		return EventRoute{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}

	// 接口级门槛，与 Resolve/Route 同一条
	if !m.allowedAt(snapshot, b.callerPackageID, def.RequiredPermission) {
		return EventRoute{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED}
	}

	event, ok := snapshot.ProviderEvent(
		b.target.packageID, b.interfaceID, b.interfaceMajor, eventID)
	if !ok || event.Meta == nil ||
		event.DefinitionGeneration != b.definitionGeneration ||
		event.ProviderGeneration != b.providerGeneration {
		// 没在契约里声明过的 event_id 一律拒绝。Provider 不能推一个契约外的
		// 事件，订阅方也不能订一个契约外的事件
		return EventRoute{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	// 事件级门槛叠加在接口级之上：一个接口可能允许任何人读状态，
	// 却只让特权方订阅原始遥测
	if !m.allowedAt(snapshot, b.callerPackageID, event.Meta.GetRequiredPermission()) {
		return EventRoute{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED}
	}

	return EventRoute{
		ProviderConn:       b.target.conn,
		ProviderEndpointID: b.target.id,
		InterfaceID:        b.interfaceID,
		InterfaceMajor:     b.interfaceMajor,
		Event:              event,
		// 内建才可能有准入。外部 registration 的 subscribeAdmit 恒为 nil，
		// 它们的事件是 endpoint 作用域的。
		Admit: b.target.subscribeAdmit,
	}, RouteError{}
}

// LookupProviderEvent 校验一次 PublishEvent：这条连接是否真的拥有该 endpoint，
// 以及该 event_id 是否在契约里声明过。
//
// 【用 Provider 自己的 endpoint 句柄查】：Provider 无法替别的 endpoint 推事件——
// 它给出的 endpoint_id 必须是它自己注册过的那个。
func (m *Module) LookupProviderEvent(
	conn ConnHandle,
	serviceEndpointID uint64,
	eventID uint32,
) (catalog.EventDefinition, RouteError) {
	if m == nil {
		return catalog.EventDefinition{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	snapshot := m.snapshot()
	if snapshot == nil {
		return catalog.EventDefinition{}, RouteError{
			Code: ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cs, ok := m.byConn[conn]
	if !ok {
		return catalog.EventDefinition{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	reg, ok := cs.registrations[serviceEndpointID]
	if !ok || !reg.live {
		return catalog.EventDefinition{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	event, ok := snapshot.ProviderEvent(
		reg.packageID, reg.interfaceID, reg.ifaceMajor, eventID)
	if !ok || event.Meta == nil {
		return catalog.EventDefinition{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	return event, RouteError{}
}

// OwnsEndpoint 回答「这条连接是否拥有这个 registration」。
//
// BindEventScope 走它：少了这道检查，任何一个系统服务都能替别的 endpoint
// 登记实例归属——进而把自己塞进别人的事件流。
//
// 【只看 registration，不看 binding】：登记归属的是【提供方】，用的是它自己
// RegisterEndpoint 拿到的句柄，与调用方那侧的 binding 是两个命名空间。
func (m *Module) OwnsEndpoint(conn ConnHandle, serviceEndpointID uint64) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cs, ok := m.byConn[conn]
	if !ok {
		return false
	}
	reg, ok := cs.registrations[serviceEndpointID]
	return ok && reg.live
}
