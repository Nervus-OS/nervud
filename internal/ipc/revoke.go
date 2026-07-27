package ipc

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/control"
	"github.com/nervus-os/nervud/internal/transfer"
)

// ControlLeaseEnded implements control.LeaseObserver. It first retires the
// exact connection-scoped wire handle and then closes every route/transfer
// derived from that lease's resource. The internal ID prevents a delayed old
// notification from deleting a replacement lease on the same connection.
func (s *Server) ControlLeaseEnded(
	caller control.ConnID,
	resource string,
	leaseID control.ID,
) {
	s.mu.Lock()
	co := s.controlConns[caller]
	s.mu.Unlock()
	if co != nil {
		co.forgetLeaseID(leaseID)
	}
	s.RevokeControl(transfer.ConnID(caller), resource)
}

// revokeEndpoint closes dispatch authority before scanning the data plane.
// This order prevents an old Dispatch.route_id from recreating a stream after
// UnregisterEndpoint has returned success.
func (s *Server) revokeEndpoint(provider *conn, endpointID, generation uint64) {
	routes := s.dispatch.revokeEndpoint(provider, endpointID, generation)
	s.finishRevokedRoutes(routes, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE, true)
	s.transfer.EndpointRevoked(
		transfer.ConnID(provider.connID), endpointID, generation)
}

// RevokePackage coordinates control-plane and data-plane revocation for
// uninstall and upgrade. It satisfies pkgregistry.PackageTransferRevoker.
func (s *Server) RevokePackage(packageID string) {
	routes := s.dispatch.revokePackage(packageID)
	s.finishRevokedRoutes(routes, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE, true)
	s.transfer.RevokePackage(packageID)
}

// RevokePermission prevents an already-dispatched method from opening a new
// stream after its caller permission has been removed.
func (s *Server) RevokePermission(packageID, permission string) {
	routes := s.dispatch.revokePermission(packageID, permission)
	s.finishRevokedRoutes(routes, ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED, true)
	s.transfer.RevokePermission(packageID, permission)
}

// RevokeResource closes every authority derived from an obsolete catalog
// resource. Dispatch is closed first so no old route can mint a new transfer;
// the lease is then invalidated before the data-plane scan completes.
func (s *Server) RevokeResource(resource string, generation uint64) {
	routes := s.dispatch.revokeResource(resource, generation)
	s.finishRevokedRoutes(routes, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION, true)
	if s.leases != nil {
		s.leases.RevokeResource(resource, generation)
	}
	s.transfer.RevokeResource(resource, generation)
}

// RevokeControl closes methods whose transfer authority depended on this
// connection's lease for resource.
func (s *Server) RevokeControl(caller transfer.ConnID, resource string) {
	routes := s.dispatch.revokeControl(caller, resource)
	s.finishRevokedRoutes(routes, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION, true)
	s.transfer.RevokeControl(caller, resource)
}

func (s *Server) finishRevokedRoutes(
	routes []*routeEntry,
	code ipcv1.StatusCode,
	notifyProvider bool,
) {
	for _, route := range routes {
		s.transfer.CloseRoute(route.routeID)
		if notifyProvider && route.target != nil {
			route.target.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_CancelDispatch{
				CancelDispatch: &ipcv1.CancelDispatch{
					RouteId: route.routeID,
					// The protocol has no permission/resource/package-revoked
					// reason. UNSPECIFIED is honest; CLIENT_CANCELLED would falsely
					// attribute a kernel revocation to an explicit caller action.
					Reason: ipcv1.CancelDispatchReason_CANCEL_DISPATCH_REASON_UNSPECIFIED,
				},
			}})
		}
		resolveRoute(route, failureResponse(route.sourceRequestID, code))
	}
}
