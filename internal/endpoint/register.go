// 本文件实现 RegisterEndpoint: Service 向 nervud 报到一个它已实现的 Interface
package endpoint

import (
	"bytes"
	"errors"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// RegisterEndpoint 处理一次 Service 报到
func (m *Module) RegisterEndpoint(conn ConnHandle, caller identity.Caller, req *ipcv1.RegisterEndpoint) *ipcv1.RegisterEndpointResult {
	reqID := req.GetRequestId()
	if m == nil {
		return registerFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)
	}

	interfaceID := req.GetInterfaceId()

	fail := func(code ipcv1.StatusCode, detail string) *ipcv1.RegisterEndpointResult {
		m.audit(caller, "endpoint.RegisterEndpoint", true, errors.New(detail), interfaceID)
		// 同时留给正在等这个组件启动的 Resolve. 没有这一步, 那边只能报
		// "等超时", 而超时不区分"没起来"与"起来了但被拒"
		m.recordRejection(caller.PackageID, caller.ComponentID, detail)
		return registerFailure(reqID, code)
	}

	// 步骤 1: 该连接必须已握手完成 (caller.ComponentID 非空, 见 ipc 的组件核对)
	if caller.ComponentID == "" {
		return fail(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION, "handshake not complete: no component id")
	}
	snapshot := m.snapshot()
	if snapshot == nil {
		return fail(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"authoritative catalog is unavailable")
	}

	// 步骤 2: Service 只能注册 manifest 已声明的 endpoint
	if m.pkgs == nil {
		return fail(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"package registry is unavailable")
	}
	entry, ok := m.pkgs.Lookup(caller.PackageID)
	if !ok {
		return fail(ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED, "unknown package")
	}
	comp, ok := entry.Manifest.Component(caller.ComponentID)
	if !ok {
		return fail(ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED, "unknown component")
	}
	if entry.ComponentDisabled(caller.ComponentID) {
		return fail(ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED, "component disabled")
	}
	if comp.Type != pkgregistry.ComponentService {
		return fail(ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED, "only service components may register endpoints")
	}

	var (
		visibility pkgregistry.Visibility
		exported   bool
	)
	for _, e := range comp.Exports {
		if e.Interface == interfaceID {
			visibility = e.Visibility
			exported = true
			break
		}
	}
	if !exported {
		return fail(ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED, "interface not declared in manifest exports")
	}

	// The signed catalog, not the wire request or manifest alone, decides which
	// package/component implements this exact interface major.
	provider, ok := snapshot.ProviderInterface(
		caller.PackageID, interfaceID, req.GetInterfaceMajor())
	if !ok ||
		provider.PackageID != caller.PackageID ||
		provider.ComponentID != caller.ComponentID ||
		provider.Definition.InterfaceID != interfaceID ||
		provider.Definition.Major != req.GetInterfaceMajor() {
		return fail(ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			"component is not a catalog-approved provider for the interface major")
	}

	// 步骤 3: 按 Export 的 Visibility 选权限 ID 并裁决
	permID := permServiceRegister
	if visibility == pkgregistry.VisibilityPackage {
		permID = permServiceRegisterPrivate
	}
	if !m.allowedAt(snapshot, caller.PackageID, permID) {
		return fail(ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED, "missing permission "+permID)
	}

	resourceHandle := req.GetResourceHandle()
	resourceGeneration, resourceOK := registrationResource(
		snapshot, provider.Definition, resourceHandle)
	if !resourceOK {
		return fail(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			"resource_handle is absent, unknown, or incompatible with the interface")
	}

	// schema hash 必须与 Catalog 里那份逐字节相等. 曾经有一条只放行
	// nervus.pkgmanagerd 空 schema 的兼容桥, 在打包链能产出 ProviderArtifacts
	// 之后已经移除 - 现在所有 Provider 一视同仁.
	reportedSchema := req.GetInterfaceSchemaHash()
	if !bytes.Equal(reportedSchema, provider.Definition.SchemaHash) {
		return fail(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			"interface schema hash does not match the catalog")
	}
	schemaHash := append([]byte(nil), provider.Definition.SchemaHash...)

	m.mu.Lock()

	// 步骤 6: 分配 conn 自己的 nextRegID, 登记 serviceRegistration
	regKey := registrationKey{pkg: caller.PackageID, comp: caller.ComponentID, iface: interfaceID}
	m.generations[regKey]++

	cs := m.connStateLocked(conn)
	cs.nextRegID++
	reg := &serviceRegistration{
		id:                   cs.nextRegID,
		conn:                 conn,
		packageID:            caller.PackageID,
		componentID:          caller.ComponentID,
		interfaceID:          interfaceID,
		ifaceMajor:           req.GetInterfaceMajor(),
		ifaceMinor:           req.GetInterfaceMinor(),
		schemaHash:           schemaHash,
		resourceHandle:       resourceHandle,
		visibility:           visibility,
		generation:           m.generations[regKey],
		definitionGeneration: provider.Definition.DefinitionGeneration,
		providerGeneration:   provider.DefinitionGeneration,
		resourceGeneration:   resourceGeneration,
		live:                 true,
	}
	cs.registrations[reg.id] = reg
	m.byInterface[interfaceID] = append(m.byInterface[interfaceID], reg)

	// 步骤 7: 若该 (pkg, comp) 有 Resolve 正在等它启动完成, 广播唤醒
	key := componentKey{pkg: caller.PackageID, comp: caller.ComponentID}
	waiters := m.pendingStarts[key]
	delete(m.pendingStarts, key)

	m.mu.Unlock()

	for _, ch := range waiters {
		close(ch)
	}

	m.audit(caller, "endpoint.RegisterEndpoint", false, nil, interfaceID)
	return &ipcv1.RegisterEndpointResult{RequestId: reqID, Outcome: &ipcv1.RegisterEndpointResult_Success{
		Success: &ipcv1.RegisterEndpointSuccess{EndpointId: reg.id},
	}}
}

func registrationResource(
	snapshot *catalog.Snapshot,
	def catalog.InterfaceDefinition,
	handle string,
) (uint64, bool) {
	if len(def.CompatibleResourceTypes) == 0 {
		return 0, handle == ""
	}
	if handle == "" {
		return 0, false
	}
	resource, ok := snapshot.ResourceByHandle(handle)
	if !ok || !compatibleResource(def, resource.ResourceType) {
		return 0, false
	}
	return resource.DefinitionGeneration, true
}

func compatibleResource(def catalog.InterfaceDefinition, resourceType string) bool {
	for _, compatible := range def.CompatibleResourceTypes {
		if compatible == resourceType {
			return true
		}
	}
	return false
}

func registerFailure(reqID uint64, code ipcv1.StatusCode) *ipcv1.RegisterEndpointResult {
	return &ipcv1.RegisterEndpointResult{RequestId: reqID, Outcome: &ipcv1.RegisterEndpointResult_Failure{
		Failure: &ipcv1.Failure{Code: code},
	}}
}
