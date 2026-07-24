// 本文件实现 RegisterEndpoint：Service 向 nervud 报到一个它已实现的 Interface
// （设计方案 §5.1）
package endpoint

import (
	"errors"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// RegisterEndpoint 处理一次 Service 报到（设计方案 §5.1）
func (m *Module) RegisterEndpoint(conn ConnHandle, caller identity.Caller, req *ipcv1.RegisterEndpoint) *ipcv1.RegisterEndpointResult {
	reqID := req.GetRequestId()
	if m == nil {
		return registerFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)
	}

	interfaceID := req.GetInterfaceId()

	fail := func(code ipcv1.StatusCode, detail string) *ipcv1.RegisterEndpointResult {
		m.audit(caller, "endpoint.RegisterEndpoint", true, errors.New(detail), interfaceID)
		return registerFailure(reqID, code)
	}

	// 步骤 1：该连接必须已握手完成（caller.ComponentID 非空，见 ipc §5.5 的组件核对）
	if caller.ComponentID == "" {
		return fail(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION, "handshake not complete: no component id")
	}

	// 步骤 2：Service 只能注册 manifest 已声明的 endpoint
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

	// 步骤 3：按 Export 的 Visibility 选权限 ID 并裁决
	permID := permServiceRegister
	if visibility == pkgregistry.VisibilityPackage {
		permID = permServiceRegisterPrivate
	}
	if !m.perm.Allowed(caller.PackageID, permID) {
		return fail(ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED, "missing permission "+permID)
	}

	// 步骤 4：resource_handle 校验——空字符串表示未指定、视为合法，非空则必须
	// 是 Resource Registry 里的一个已知句柄（Resource模块设计方案.md §4.3）
	resourceHandle := req.GetResourceHandle()
	if resourceHandle != "" && !m.resources.Valid(resourceHandle) {
		return fail(ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT, "unsupported resource_handle")
	}

	// 步骤 5：schema_hash 只记录、不比对（见设计方案 §6.5）
	var schemaHash []byte
	if h := req.GetInterfaceSchemaHash(); len(h) > 0 {
		schemaHash = append([]byte(nil), h...)
	}

	m.mu.Lock()

	// 步骤 6：分配 conn 自己的 nextRegID，登记 serviceRegistration
	regKey := registrationKey{pkg: caller.PackageID, comp: caller.ComponentID, iface: interfaceID}
	m.generations[regKey]++

	cs := m.connStateLocked(conn)
	cs.nextRegID++
	reg := &serviceRegistration{
		id:             cs.nextRegID,
		conn:           conn,
		packageID:      caller.PackageID,
		componentID:    caller.ComponentID,
		interfaceID:    interfaceID,
		ifaceMajor:     req.GetInterfaceMajor(),
		ifaceMinor:     req.GetInterfaceMinor(),
		schemaHash:     schemaHash,
		resourceHandle: resourceHandle,
		visibility:     visibility,
		generation:     m.generations[regKey],
		live:           true,
	}
	cs.registrations[reg.id] = reg
	m.byInterface[interfaceID] = append(m.byInterface[interfaceID], reg)

	// 步骤 7：若该 (pkg, comp) 有 Resolve 正在等它启动完成，广播唤醒
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

func registerFailure(reqID uint64, code ipcv1.StatusCode) *ipcv1.RegisterEndpointResult {
	return &ipcv1.RegisterEndpointResult{RequestId: reqID, Outcome: &ipcv1.RegisterEndpointResult_Failure{
		Failure: &ipcv1.Failure{Code: code},
	}}
}
