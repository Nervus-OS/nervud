// 本文件实现 ResolveEndpoint：Caller 把 interface_id 解析成本连接作用域的
// endpoint_id，解析时完成一次权限裁决（设计方案 §5.2）
package endpoint

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/identity"
)

// ResolveEndpoint 处理一次 Caller 发现（设计方案 §5.2）
func (m *Module) ResolveEndpoint(conn ConnHandle, caller identity.Caller, req *ipcv1.ResolveEndpoint) *ipcv1.ResolveEndpointResult {
	reqID := req.GetRequestId()
	if m == nil {
		return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
	}

	interfaceID := req.GetInterfaceId()

	// 决策 1（设计方案 §6.1）：explicit_component 在 v1 恒 PERMISSION_DENIED——
	// manifest 目前没有字段能声明"绑定某个具体 Component"，非空必然找不到对应
	// 声明，直接拒绝即是正确行为，不构成技术债
	if req.GetExplicitComponent() != "" {
		m.audit(caller, "endpoint.ResolveEndpoint", true, errExplicitComponent, interfaceID)
		return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
	}

	// 步骤 2：Selector 校验
	resourceHandle, ok := resolveSelector(req.GetSelector())
	if !ok {
		m.audit(caller, "endpoint.ResolveEndpoint", true, errResourceNotFound, interfaceID)
		return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_NOT_FOUND)
	}

	requiredPermission := ""
	if entry, ok := m.catalog.Lookup(interfaceID); ok {
		requiredPermission = entry.RequiredPermission
	}

	for {
		m.mu.Lock()
		candidates := m.visibleCandidatesLocked(caller.PackageID, interfaceID)

		switch len(candidates) {
		case 1:
			cand := candidates[0]

			// 步骤 4：版本协商
			if req.GetMinInterfaceMajor() > cand.ifaceMajor || req.GetMaxInterfaceMajor() < cand.ifaceMajor {
				m.mu.Unlock()
				m.audit(caller, "endpoint.ResolveEndpoint", true, errVersionMismatch, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_VERSION_MISMATCH)
			}

			// 步骤 5：权限裁决——架构总览 §7 待办列表里等待的那次真正调用
			if requiredPermission != "" && !m.perm.Allowed(caller.PackageID, requiredPermission) {
				m.mu.Unlock()
				m.audit(caller, "endpoint.ResolveEndpoint", true, errPermissionDenied, requiredPermission)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
			}

			// 步骤 7：分配本连接 nextEndpointID，创建 binding
			cs := m.connStateLocked(conn)
			cs.nextEndpointID++
			id := cs.nextEndpointID
			cs.bindings[id] = &binding{
				id:                 id,
				conn:               conn,
				callerPackageID:    caller.PackageID,
				target:             cand,
				targetGeneration:   cand.generation,
				interfaceMajor:     cand.ifaceMajor,
				interfaceMinor:     cand.ifaceMinor,
				requiredPermission: requiredPermission,
				resourceHandle:     resourceHandle,
			}
			m.mu.Unlock()

			m.audit(caller, "endpoint.ResolveEndpoint", false, nil, interfaceID)
			return &ipcv1.ResolveEndpointResult{RequestId: reqID, Outcome: &ipcv1.ResolveEndpointResult_Success{
				Success: &ipcv1.ResolveEndpointSuccess{
					EndpointId:          id,
					InterfaceMajor:      cand.ifaceMajor,
					InterfaceMinor:      cand.ifaceMinor,
					InterfaceSchemaHash: cand.schemaHash,
					// resource_handle 是已解析的公开 Resource 句柄（来自 Selector 校验，
					// 见 resolveSelector），不是 Service 注册时上报的原始值——v1 二者在
					// base.main 场景下总相等，但语义上前者才是"这次 Resolve 解析到的"
					ResourceHandle: resourceHandle,
				},
			}}

		case 0:
			m.mu.Unlock()

			// 步骤 6：尝试 on-demand 拉起
			pkg, comp, found := m.findOnDemandCandidate(caller.PackageID, interfaceID)
			if !found {
				m.audit(caller, "endpoint.ResolveEndpoint", true, errInterfaceNotFound, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_INTERFACE_NOT_FOUND)
			}

			started, err := m.tryOnDemandStart(pkg, comp)
			if err != nil {
				// EnsureStarted 失败（如组件被禁用）：原样映射为 FAILED_PRECONDITION
				m.audit(caller, "endpoint.ResolveEndpoint", true, err, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
			}
			if !started {
				m.audit(caller, "endpoint.ResolveEndpoint", true, errOnDemandTimeout, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_NOT_FOUND)
			}

			// 被唤醒：回到候选检查，不假设"广播即成功"（设计方案 §5.2 第 6 步）
			continue

		default:
			// v1 单一执行器模型下理论不会出现：出现即装配矛盾的信号
			m.mu.Unlock()
			m.audit(caller, "endpoint.ResolveEndpoint", true, errAmbiguous, interfaceID)
			return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
				ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_AMBIGUOUS)
		}
	}
}

// resolveSelector 校验 ResourceSelector 并返回对应的 resource_handle
//
// v1 [REWRITE-v1] 只有 base.main 一种合法取值：留空视为隐式取该值，非空则必须
// 精确匹配（设计方案 §5.2 第 2 步 / §6.3）。internal/resource 落地后这里要改成
// 真正查 Resource Registry
func resolveSelector(sel *ipcv1.ResourceSelector) (string, bool) {
	if sel == nil {
		return resourceHandleBaseMain, true
	}
	if sel.GetType() == "" && sel.GetRole() == "" {
		return resourceHandleBaseMain, true
	}
	if sel.GetType() == resourceTypeMotionBase && sel.GetRole() == resourceRoleMain {
		return resourceHandleBaseMain, true
	}
	return "", false
}

// resolveFailure 组装一个带 ResolveEndpointErrorDetail 的失败结果。
// reason 为 UNSPECIFIED 时省略 ErrorDetail（如 PERMISSION_DENIED 不需要它）
func resolveFailure(reqID uint64, code ipcv1.StatusCode, reason ipcv1.ResolveEndpointReason) *ipcv1.ResolveEndpointResult {
	f := &ipcv1.Failure{Code: code}
	if reason != ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED {
		if b, err := proto.Marshal(&ipcv1.ResolveEndpointErrorDetail{Reason: reason}); err == nil {
			f.ErrorDetail = b
		}
	}
	return &ipcv1.ResolveEndpointResult{RequestId: reqID, Outcome: &ipcv1.ResolveEndpointResult_Failure{Failure: f}}
}
