// 本文件实现 ResolveEndpoint: Caller 把 interface_id 解析成本连接作用域的
// endpoint_id, 并在绑定前完成权限裁决
package endpoint

import (
	"bytes"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

// ResolveEndpoint 处理一次 Caller 发现并返回连接作用域的绑定
func (m *Module) ResolveEndpoint(conn ConnHandle, caller identity.Caller, req *ipcv1.ResolveEndpoint) *ipcv1.ResolveEndpointResult {
	reqID := req.GetRequestId()
	if m == nil {
		return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
	}

	interfaceID := req.GetInterfaceId()
	snapshot := m.snapshot()
	if snapshot == nil {
		m.audit(caller, "endpoint.ResolveEndpoint", true, errInterfaceNotFound, interfaceID)
		return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_INTERFACE_NOT_FOUND)
	}

	// explicit_component 在 v1 恒为 PERMISSION_DENIED, 因为
	// manifest 目前没有字段能声明"绑定某个具体 Component", 非空必然找不到对应
	// 声明, 直接拒绝即是正确行为, 不构成技术债
	if req.GetExplicitComponent() != "" {
		m.audit(caller, "endpoint.ResolveEndpoint", true, errExplicitComponent, interfaceID)
		return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
	}

	if req.GetMaxInterfaceMajor() < req.GetMinInterfaceMajor() {
		m.audit(caller, "endpoint.ResolveEndpoint", true, errVersionMismatch, interfaceID)
		return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_VERSION_MISMATCH)
	}

	attemptedStart := false
	for {
		m.mu.Lock()
		visible := m.visibleCandidatesLocked(caller.PackageID, interfaceID)
		var (
			candidates       []resolvedCandidate
			versionCandidate bool
			resourceMismatch bool
		)
		for _, reg := range visible {
			if reg.ifaceMajor < req.GetMinInterfaceMajor() ||
				reg.ifaceMajor > req.GetMaxInterfaceMajor() {
				continue
			}
			versionCandidate = true
			def, provider, valid := registrationInSnapshot(snapshot, reg)
			if !valid {
				continue
			}
			resourceHandle, resourceGeneration, valid :=
				resolveInterfaceResource(snapshot, def, req.GetSelector())
			if !valid || resourceHandle != reg.resourceHandle ||
				resourceGeneration != reg.resourceGeneration {
				resourceMismatch = true
				continue
			}
			candidates = append(candidates, resolvedCandidate{
				registration:       reg,
				definition:         def,
				provider:           provider,
				resourceHandle:     resourceHandle,
				resourceGeneration: resourceGeneration,
			})
		}

		switch len(candidates) {
		case 1:
			candidate := candidates[0]
			cand := candidate.registration
			requiredPermission := candidate.definition.RequiredPermission

			// 步骤 5: 绑定前查询当前授权, 避免 Resolve 只依赖安装期裁决
			if !m.allowedAt(snapshot, caller.PackageID, requiredPermission) {
				m.mu.Unlock()
				m.audit(caller, "endpoint.ResolveEndpoint", true, errPermissionDenied, requiredPermission)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
			}

			// 步骤 7: 分配本连接 nextEndpointID, 创建 binding
			cs := m.connStateLocked(conn)
			cs.nextEndpointID++
			id := cs.nextEndpointID
			cs.bindings[id] = &binding{
				id:                   id,
				conn:                 conn,
				callerPackageID:      caller.PackageID,
				target:               cand,
				targetGeneration:     cand.generation,
				interfaceID:          interfaceID,
				interfaceMajor:       cand.ifaceMajor,
				interfaceMinor:       cand.ifaceMinor,
				requiredPermission:   requiredPermission,
				resourceHandle:       candidate.resourceHandle,
				definitionGeneration: candidate.definition.DefinitionGeneration,
				providerGeneration:   candidate.provider.DefinitionGeneration,
				resourceGeneration:   candidate.resourceGeneration,
			}
			m.mu.Unlock()

			m.audit(caller, "endpoint.ResolveEndpoint", false, nil, interfaceID)
			return &ipcv1.ResolveEndpointResult{RequestId: reqID, Outcome: &ipcv1.ResolveEndpointResult_Success{
				Success: &ipcv1.ResolveEndpointSuccess{
					EndpointId:          id,
					InterfaceMajor:      cand.ifaceMajor,
					InterfaceMinor:      cand.ifaceMinor,
					InterfaceSchemaHash: append([]byte(nil), candidate.definition.SchemaHash...),
					ResourceHandle:      candidate.resourceHandle,
					CatalogRevision:     snapshot.Revision(),
				},
			}}

		case 0:
			m.mu.Unlock()

			if len(visible) != 0 {
				if !versionCandidate {
					m.audit(caller, "endpoint.ResolveEndpoint", true, errVersionMismatch, interfaceID)
					return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
						ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_VERSION_MISMATCH)
				}
				if resourceMismatch {
					m.audit(caller, "endpoint.ResolveEndpoint", true, errResourceNotFound, interfaceID)
					return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
						ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_NOT_FOUND)
				}
				m.audit(caller, "endpoint.ResolveEndpoint", true, errInterfaceNotFound, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_INTERFACE_NOT_FOUND)
			}

			// 步骤 6: 尝试 on-demand 拉起. A rejected or stale
			// registration may wake the waiter, but it never grants a second
			// unbounded start attempt.
			if attemptedStart {
				m.audit(caller, "endpoint.ResolveEndpoint", true, errInterfaceNotFound, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_INTERFACE_NOT_FOUND)
			}
			candidate, failure := m.authorizeOnDemandStart(snapshot, caller.PackageID, req)
			switch failure {
			case onDemandPermissionDenied:
				m.audit(caller, "endpoint.ResolveEndpoint", true, errPermissionDenied, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
			case onDemandVersionMismatch:
				m.audit(caller, "endpoint.ResolveEndpoint", true, errVersionMismatch, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_VERSION_MISMATCH)
			case onDemandResourceMismatch:
				m.audit(caller, "endpoint.ResolveEndpoint", true, errResourceNotFound, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_NOT_FOUND)
			case onDemandAmbiguous:
				m.audit(caller, "endpoint.ResolveEndpoint", true, errAmbiguous, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_AMBIGUOUS)
			case onDemandNotFound:
				m.audit(caller, "endpoint.ResolveEndpoint", true, errInterfaceNotFound, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_INTERFACE_NOT_FOUND)
			case onDemandAuthorized:
			}

			attemptedStart = true
			started, err := m.tryOnDemandStart(candidate.pkg, candidate.comp)
			if err != nil {
				// EnsureStarted 失败 (如组件被禁用): 原样映射为 FAILED_PRECONDITION
				m.audit(caller, "endpoint.ResolveEndpoint", true, err, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED)
			}
			if !started {
				m.audit(caller, "endpoint.ResolveEndpoint", true, errOnDemandTimeout, interfaceID)
				return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
					ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_NOT_FOUND)
			}

			// 被唤醒: 回到候选检查, 不假设"广播即成功"
			continue

		default:
			// v1 单一执行器模型下理论不会出现: 出现即装配矛盾的信号
			m.mu.Unlock()
			m.audit(caller, "endpoint.ResolveEndpoint", true, errAmbiguous, interfaceID)
			return resolveFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
				ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_AMBIGUOUS)
		}
	}
}

type resolvedCandidate struct {
	registration       *serviceRegistration
	definition         catalog.InterfaceDefinition
	provider           catalog.ProviderInterface
	resourceHandle     string
	resourceGeneration uint64
}

type onDemandFailure uint8

const (
	onDemandAuthorized onDemandFailure = iota
	onDemandNotFound
	onDemandVersionMismatch
	onDemandPermissionDenied
	onDemandResourceMismatch
	onDemandAmbiguous
)

// authorizeOnDemandStart proves the side effect itself is authorized. A
// manifest export alone is not enough: the exact package/component must be a
// catalog-approved Provider in the requested major range, the interface
// permission must already be granted, and the selector must resolve against
// that same immutable snapshot.
func (m *Module) authorizeOnDemandStart(
	snapshot *catalog.Snapshot,
	callerPackageID string,
	req *ipcv1.ResolveEndpoint,
) (componentKey, onDemandFailure) {
	if snapshot == nil || req == nil {
		return componentKey{}, onDemandNotFound
	}
	manifestCandidates := m.manifestOnDemandCandidates(
		callerPackageID, req.GetInterfaceId())
	if len(manifestCandidates) == 0 {
		return componentKey{}, onDemandNotFound
	}

	allMatch := false
	for _, provider := range snapshot.ProviderInterfaces(
		req.GetInterfaceId(), 0, ^uint32(0)) {
		key := componentKey{pkg: provider.PackageID, comp: provider.ComponentID}
		if _, ok := manifestCandidates[key]; ok {
			allMatch = true
			break
		}
	}
	if !allMatch {
		return componentKey{}, onDemandNotFound
	}

	rangeMatch := false
	permissionDenied := false
	resourceMismatch := false
	authorized := make(map[componentKey]struct{})
	var selected componentKey
	for _, provider := range snapshot.ProviderInterfaces(
		req.GetInterfaceId(), req.GetMinInterfaceMajor(), req.GetMaxInterfaceMajor()) {
		key := componentKey{pkg: provider.PackageID, comp: provider.ComponentID}
		if _, ok := manifestCandidates[key]; !ok {
			continue
		}
		rangeMatch = true
		if !m.allowedAt(snapshot, callerPackageID, provider.Definition.RequiredPermission) {
			permissionDenied = true
			continue
		}
		if _, _, ok := resolveInterfaceResource(
			snapshot, provider.Definition, req.GetSelector()); !ok {
			resourceMismatch = true
			continue
		}
		if _, duplicate := authorized[key]; !duplicate {
			authorized[key] = struct{}{}
			selected = key
		}
	}

	switch {
	case len(authorized) > 1:
		return componentKey{}, onDemandAmbiguous
	case len(authorized) == 1:
		return selected, onDemandAuthorized
	case !rangeMatch:
		return componentKey{}, onDemandVersionMismatch
	case permissionDenied:
		return componentKey{}, onDemandPermissionDenied
	case resourceMismatch:
		return componentKey{}, onDemandResourceMismatch
	default:
		return componentKey{}, onDemandNotFound
	}
}

func registrationInSnapshot(
	snapshot *catalog.Snapshot,
	reg *serviceRegistration,
) (catalog.InterfaceDefinition, catalog.ProviderInterface, bool) {
	if snapshot == nil || reg == nil || !reg.live {
		return catalog.InterfaceDefinition{}, catalog.ProviderInterface{}, false
	}
	def, ok := snapshot.Interface(reg.interfaceID, reg.ifaceMajor)
	if !ok || def.DefinitionGeneration != reg.definitionGeneration ||
		!bytes.Equal(def.SchemaHash, reg.schemaHash) {
		return catalog.InterfaceDefinition{}, catalog.ProviderInterface{}, false
	}
	provider, ok := snapshot.ProviderInterface(
		reg.packageID, reg.interfaceID, reg.ifaceMajor)
	if !ok || provider.ComponentID != reg.componentID ||
		provider.DefinitionGeneration != reg.providerGeneration ||
		provider.Definition.DefinitionGeneration != reg.definitionGeneration {
		return catalog.InterfaceDefinition{}, catalog.ProviderInterface{}, false
	}
	return def, provider, true
}

// resolveInterfaceResource applies the interface's catalog-owned default and
// compatibility set. Interfaces without resources resolve to the empty handle;
// they cannot be rebound to an arbitrary resource.
func resolveInterfaceResource(
	snapshot *catalog.Snapshot,
	def catalog.InterfaceDefinition,
	sel *ipcv1.ResourceSelector,
) (string, uint64, bool) {
	if snapshot == nil {
		return "", 0, false
	}
	// 空 selector 回落到接口自己声明的默认资源.
	//
	// 这与 v1 那条隐式默认不是一回事: v1 由内核写死 {motion.base, main},
	// 任何接口留空都拿到底盘; 这里的默认由接口的 ProviderDescriptor 声明,
	// 没声明就是没有默认, 解析不到. 语义由接口数据决定, 不由内核写死.
	if catalog.SelectorIsEmpty(sel) {
		resourceType, role := def.DefaultResourceType, def.DefaultResourceRole
		if resourceType == "" && role == "" {
			// 不绑资源的接口: 留空即正确. 绑资源却没声明默认的接口: 必须显式给 selector
			return "", 0, len(def.CompatibleResourceTypes) == 0
		}
		if len(def.CompatibleResourceTypes) == 0 {
			return "", 0, false
		}
		resource, ok := snapshot.ResolveResource(resourceType, role)
		if !ok || !compatibleResource(def, resource.ResourceType) {
			return "", 0, false
		}
		return resource.Handle, resource.DefinitionGeneration, true
	}

	// 非空 selector 走完整选择: type / role 精确匹配 + labels AND 过滤 +
	// 多候选策略 (未指定 fail closed 为 REQUIRE_UNIQUE)
	if len(def.CompatibleResourceTypes) == 0 {
		return "", 0, false
	}
	matched, ok := catalog.SelectResources(snapshot, sel)
	if !ok {
		// 命中 0 个, 或命中多个而策略要求唯一. 两种都是调用方要改的事,
		// 统一以"解析不到"表达 - ResolveEndpoint 会回 FAILED_PRECONDITION
		return "", 0, false
	}
	resource := matched[0]
	if !compatibleResource(def, resource.ResourceType) {
		return "", 0, false
	}
	return resource.Handle, resource.DefinitionGeneration, true
}

// resolveFailure 组装一个带 ResolveEndpointErrorDetail 的失败结果.
// reason 为 UNSPECIFIED 时省略 ErrorDetail (如 PERMISSION_DENIED 不需要它)
func resolveFailure(reqID uint64, code ipcv1.StatusCode, reason ipcv1.ResolveEndpointReason) *ipcv1.ResolveEndpointResult {
	f := &ipcv1.Failure{Code: code}
	if reason != ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_UNSPECIFIED {
		if b, err := proto.Marshal(&ipcv1.ResolveEndpointErrorDetail{Reason: reason}); err == nil {
			f.ErrorDetail = b
		}
	}
	return &ipcv1.ResolveEndpointResult{RequestId: reqID, Outcome: &ipcv1.ResolveEndpointResult_Failure{Failure: f}}
}
