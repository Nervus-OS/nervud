// 本文件实现 Route, UnregisterEndpoint 与连接关闭时的生命周期失效
package endpoint

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

// Route 供 ipc 的 handleRequest 使用: 拿到 endpoint_id 后查一次"转给谁,
// 这次调用是否仍然合法"
//
// 每次调用都重新做一次权限复核 (而不是只信 Resolve 时检查过一次) - 这正是
// "解析 endpoint 时检查一次权限, 每次调用时仍做快速权限与存活
// 复核, 以支持动态撤权"的字面要求, 也是纯被动检查也能保证"权限撤销后下一次
// 调用必然失败"的原因
func (m *Module) Route(
	conn ConnHandle,
	endpointID uint64,
	methodID uint32,
) (RouteInfo, RouteError) {
	if m == nil {
		return RouteInfo{}, RouteError{
			Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, Reason: "endpoint module is nil"}
	}
	snapshot := m.snapshot()
	if snapshot == nil {
		return RouteInfo{}, RouteError{
			Code: ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION, Reason: "catalog snapshot unavailable"}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cs, ok := m.byConn[conn]
	if !ok {
		return RouteInfo{}, RouteError{
			Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, Reason: "caller connection has no endpoint state"}
	}
	b, ok := cs.bindings[endpointID]
	if !ok {
		return RouteInfo{}, RouteError{
			Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, Reason: "endpoint_id not bound on this connection"}
	}
	if b.target == nil || !b.target.live {
		// Provider 的注册已失效 (进程退出/连接断开), 而调用方还拿着上一次 Resolve
		// 的 endpoint_id. 对 on-demand 组件, 它空闲退出后必然如此.
		return RouteInfo{}, RouteError{
			Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, Reason: "provider registration is no longer live"}
	}
	if b.targetGeneration != b.target.generation {
		// Provider 重启过: 同一三元组又注册一次, 世代号递增. 旧 binding 必须失效,
		// 否则调用会打到新进程上而调用方以为还是旧的.
		return RouteInfo{}, RouteError{
			Code:   ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			Reason: "provider restarted (registration generation moved)"}
	}
	def, provider, valid := registrationInSnapshot(snapshot, b.target)
	if !valid {
		return RouteInfo{}, RouteError{
			Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, Reason: "provider registration not in current catalog"}
	}
	if def.DefinitionGeneration != b.definitionGeneration ||
		provider.DefinitionGeneration != b.providerGeneration {
		// Catalog 换了一版 (装/卸包会重建它), 绑定时的定义世代与现在不一致.
		return RouteInfo{}, RouteError{
			Code:   ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			Reason: "catalog definition generation moved since bind"}
	}
	if b.interfaceID != b.target.interfaceID ||
		b.interfaceMajor != b.target.ifaceMajor {
		return RouteInfo{}, RouteError{
			Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, Reason: "binding interface does not match registration"}
	}
	if b.resourceHandle == "" {
		if b.resourceGeneration != 0 || len(def.CompatibleResourceTypes) != 0 {
			return RouteInfo{}, RouteError{
				Code:   ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
				Reason: "interface needs a resource but binding has none"}
		}
	} else {
		resource, exists := snapshot.ResourceByHandle(b.resourceHandle)
		if !exists ||
			resource.DefinitionGeneration != b.resourceGeneration ||
			!compatibleResource(def, resource.ResourceType) ||
			b.target.resourceHandle != b.resourceHandle {
			return RouteInfo{}, RouteError{
				Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND, Reason: "bound resource is gone or incompatible"}
		}
	}

	if !m.allowedAt(snapshot, b.callerPackageID, def.RequiredPermission) {
		return RouteInfo{}, RouteError{
			Code:   ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			Reason: "caller lacks interface permission " + def.RequiredPermission}
	}

	method, ok := snapshot.ProviderMethod(
		b.target.packageID, b.interfaceID, b.interfaceMajor, methodID)
	if !ok || method.Meta == nil {
		// 该 Provider 的这个接口里没有这个 method_id: 调用方写错编号, 或
		// Provider 的 schema 与 Catalog 里的不是同一版.
		return RouteInfo{}, RouteError{
			Code:   ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			Reason: "method_id not declared by this provider's interface"}
	}
	if method.DefinitionGeneration != b.definitionGeneration ||
		method.ProviderGeneration != b.providerGeneration {
		return RouteInfo{}, RouteError{
			Code:   ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			Reason: "method generation moved since bind"}
	}
	methodPermission := method.Meta.GetRequiredPermission()
	if !m.allowedAt(snapshot, b.callerPackageID, methodPermission) {
		return RouteInfo{}, RouteError{
			Code:   ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			Reason: "caller lacks method permission " + methodPermission}
	}
	requiredPermissions := uniquePermissions(def.RequiredPermission, methodPermission)

	return RouteInfo{
		TargetConn:             b.target.conn,
		ServiceEndpointID:      b.target.id,
		ProviderPackageID:      b.target.packageID,
		ProviderComponentID:    b.target.componentID,
		InterfaceID:            b.interfaceID,
		InterfaceMajor:         b.interfaceMajor,
		InterfaceMinor:         b.target.ifaceMinor,
		InterfaceSchemaHash:    append([]byte(nil), b.target.schemaHash...),
		ResourceHandle:         b.resourceHandle,
		Method:                 method,
		RegistrationGeneration: b.targetGeneration,
		DefinitionGeneration:   b.definitionGeneration,
		ProviderGeneration:     b.providerGeneration,
		ResourceGeneration:     b.resourceGeneration,
		RequiredPermissions:    requiredPermissions,
		Builtin:                b.target.builtin,
	}, RouteError{}
}

func uniquePermissions(interfacePermission, methodPermission string) []string {
	switch {
	case interfacePermission == "" && methodPermission == "":
		return nil
	case interfacePermission == "":
		return []string{methodPermission}
	case methodPermission == "" || methodPermission == interfacePermission:
		return []string{interfacePermission}
	default:
		return []string{interfacePermission, methodPermission}
	}
}

// UnregisterEndpoint 撤下一个 Service 侧的 registration
//
// req.Drain 在 v1 未接线: 执行层没有在途 Dispatch 追踪, drain=true 退化为
// 立即失效; v1 不保留可等待旧调用完成的双版本 registration
func (m *Module) UnregisterEndpoint(conn ConnHandle, req *ipcv1.UnregisterEndpoint) *ipcv1.UnregisterEndpointResult {
	reqID := req.GetRequestId()
	if m == nil {
		return unregisterFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cs, ok := m.byConn[conn]
	if !ok {
		return unregisterFailure(reqID, ipcv1.StatusCode_STATUS_CODE_NOT_FOUND)
	}
	reg, ok := cs.registrations[req.GetEndpointId()]
	if !ok {
		return unregisterFailure(reqID, ipcv1.StatusCode_STATUS_CODE_NOT_FOUND)
	}

	delete(cs.registrations, req.GetEndpointId())
	reg.live = false
	m.removeFromInterfaceIndexLocked(reg)

	return &ipcv1.UnregisterEndpointResult{RequestId: reqID, Outcome: &ipcv1.UnregisterEndpointResult_Success{
		Success: &ipcv1.UnregisterEndpointSuccess{},
	}}
}

func unregisterFailure(reqID uint64, code ipcv1.StatusCode) *ipcv1.UnregisterEndpointResult {
	return &ipcv1.UnregisterEndpointResult{RequestId: reqID, Outcome: &ipcv1.UnregisterEndpointResult_Failure{
		Failure: &ipcv1.Failure{Code: code},
	}}
}

// ConnClosed 由 ipc 在连接的 serve 循环退出时调用一次, 清理该连接名下的
// 全部 registration/binding
//
//   - Service 连接: 名下全部 serviceRegistration 被标记失效并从 byInterface
//     摘掉, 引用它们的 binding 在下次 Route 时据此判定失效
//   - Caller 连接: 直接丢弃该连接名下全部 binding, 无需通知任何人 - UDS 断线后
//     全部 endpoint 失效, 重连必须重新 Resolve
func (m *Module) ConnClosed(conn ConnHandle) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cs, ok := m.byConn[conn]
	if !ok {
		return
	}
	delete(m.byConn, conn)

	for _, reg := range cs.registrations {
		reg.live = false
		m.removeFromInterfaceIndexLocked(reg)
	}
}
