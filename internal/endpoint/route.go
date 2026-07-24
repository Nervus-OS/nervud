// 本文件实现 Route、UnregisterEndpoint 与连接关闭时的生命周期失效
package endpoint

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
)

// Route 供 ipc 的 handleRequest 使用：拿到 endpoint_id 后查一次"转给谁、
// 这次调用是否仍然合法"
//
// 每次调用都重新做一次权限复核（而不是只信 Resolve 时检查过一次） - 这正是
// "解析 endpoint 时检查一次权限，每次调用时仍做快速权限与存活
// 复核，以支持动态撤权"的字面要求，也是纯被动检查也能保证"权限撤销后下一次
// 调用必然失败"的原因
func (m *Module) Route(conn ConnHandle, endpointID uint64) (RouteInfo, RouteError) {
	if m == nil {
		return RouteInfo{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cs, ok := m.byConn[conn]
	if !ok {
		return RouteInfo{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	b, ok := cs.bindings[endpointID]
	if !ok || !b.target.live {
		return RouteInfo{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	}
	if b.requiredPermission != "" && !m.perm.Allowed(b.callerPackageID, b.requiredPermission) {
		return RouteInfo{}, RouteError{Code: ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED}
	}

	return RouteInfo{
		TargetConn:        b.target.conn,
		ServiceEndpointID: b.target.id,
		ResourceHandle:    b.resourceHandle,
	}, RouteError{}
}

// UnregisterEndpoint 撤下一个 Service 侧的 registration
//
// req.Drain 在 v1 未接线：执行层没有在途 Dispatch 追踪，drain=true 退化为
// 立即失效；v1 不保留可等待旧调用完成的双版本 registration
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

// ConnClosed 由 ipc 在连接的 serve 循环退出时调用一次，清理该连接名下的
// 全部 registration/binding
//
//   - Service 连接：名下全部 serviceRegistration 被标记失效并从 byInterface
//     摘掉，引用它们的 binding 在下次 Route 时据此判定失效
//   - Caller 连接：直接丢弃该连接名下全部 binding，无需通知任何人 - UDS 断线后
//     全部 endpoint 失效，重连必须重新 Resolve
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
