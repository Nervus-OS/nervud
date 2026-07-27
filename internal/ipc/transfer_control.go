package ipc

import (
	transferv1 "github.com/nervus-os/nervus-ipc/protocol/interface/transferv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/transfer"
)

// TransferBuiltinHandler implements nervus.interface.transfer.control without
// knowing anything about Camera, Microphone, or future capabilities. The only
// authority it accepts is a live Dispatch route whose MethodMeta declares a
// TransferPolicy.
func (s *Server) TransferBuiltinHandler() endpoint.BuiltinHandler {
	return func(call endpoint.BuiltinCall) endpoint.BuiltinResult {
		co, ok := call.Conn.(*conn)
		if !ok || co == nil || co.s != s {
			return endpoint.BuiltinResult{
				Code: ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			}
		}
		if err := call.Context.Err(); err != nil {
			return endpoint.BuiltinResult{
				Code: ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED,
			}
		}

		switch transferv1.TransferControlMethod(call.MethodID) {
		case transferv1.TransferControlMethod_TRANSFER_CONTROL_METHOD_BEGIN_TRANSFER:
			return s.beginTransferBuiltin(co, call.Payload)
		case transferv1.TransferControlMethod_TRANSFER_CONTROL_METHOD_COMMIT_TRANSFER:
			return s.commitTransferBuiltin(co, call.Payload)
		case transferv1.TransferControlMethod_TRANSFER_CONTROL_METHOD_ABORT_TRANSFER:
			return s.abortTransferBuiltin(co, call.Payload)
		default:
			return endpoint.BuiltinResult{
				Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			}
		}
	}
}

func (s *Server) beginTransferBuiltin(
	provider *conn,
	payload []byte,
) endpoint.BuiltinResult {
	var request transferv1.BeginTransferRequest
	if err := proto.Unmarshal(payload, &request); err != nil {
		return endpoint.BuiltinResult{
			Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
		}
	}

	entry, ok := s.dispatch.origin(request.GetOriginRouteId(), provider)
	if !ok {
		return endpoint.BuiltinResult{
			Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
		}
	}
	if methodRequiresControl(entry.route.Method.Meta) {
		if entry.route.ResourceHandle == "" || s.leases == nil {
			return endpoint.BuiltinResult{
				Code: ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			}
		}
		if _, err := s.leases.CheckResource(
			entry.source.connID,
			entry.route.ResourceHandle,
			entry.route.ResourceGeneration,
		); err != nil {
			return endpoint.BuiltinResult{
				Code: ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			}
		}
	}

	response, err := s.transfer.Begin(transfer.Origin{
		RouteID:            entry.routeID,
		Token:              entry.token,
		Deadline:           entry.deadline,
		Caller:             transferPeer(entry.source),
		Provider:           transferPeer(entry.target),
		ProviderEndpointID: entry.route.ServiceEndpointID,
		BindingGeneration:  entry.route.RegistrationGeneration,
		MethodID:           entry.methodID,
		ResourceHandle:     entry.route.ResourceHandle,
		ResourceGeneration: entry.route.ResourceGeneration,
		RequiredPermissions: append(
			[]string(nil), entry.route.RequiredPermissions...),
		RequiresControlLease: methodRequiresControl(entry.route.Method.Meta),
		Policy:               entry.route.Method.Meta.GetTransfer(),
	}, &request)
	if err != nil {
		return endpoint.BuiltinResult{Code: transfer.CodeOf(err)}
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(response)
	if err != nil {
		return endpoint.BuiltinResult{
			Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL,
		}
	}
	return endpoint.BuiltinResult{
		Payload: wire,
		Code:    ipcv1.StatusCode_STATUS_CODE_OK,
	}
}

func (s *Server) commitTransferBuiltin(
	provider *conn,
	payload []byte,
) endpoint.BuiltinResult {
	var request transferv1.CommitTransferRequest
	if err := proto.Unmarshal(payload, &request); err != nil {
		return endpoint.BuiltinResult{
			Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
		}
	}
	if err := s.transfer.Commit(
		transfer.ConnID(provider.connID), request.GetTransferId()); err != nil {
		return endpoint.BuiltinResult{Code: transfer.CodeOf(err)}
	}
	wire, err := proto.Marshal(&transferv1.CommitTransferResponse{})
	if err != nil {
		return endpoint.BuiltinResult{
			Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL,
		}
	}
	return endpoint.BuiltinResult{
		Payload: wire,
		Code:    ipcv1.StatusCode_STATUS_CODE_OK,
	}
}

func (s *Server) abortTransferBuiltin(
	provider *conn,
	payload []byte,
) endpoint.BuiltinResult {
	var request transferv1.AbortTransferRequest
	if err := proto.Unmarshal(payload, &request); err != nil {
		return endpoint.BuiltinResult{
			Code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
		}
	}
	if err := s.transfer.Abort(
		transfer.ConnID(provider.connID), request.GetTransferId()); err != nil {
		return endpoint.BuiltinResult{Code: transfer.CodeOf(err)}
	}
	wire, err := proto.Marshal(&transferv1.AbortTransferResponse{})
	if err != nil {
		return endpoint.BuiltinResult{
			Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL,
		}
	}
	return endpoint.BuiltinResult{
		Payload: wire,
		Code:    ipcv1.StatusCode_STATUS_CODE_OK,
	}
}

func transferPeer(co *conn) transfer.Peer {
	if co == nil {
		return transfer.Peer{}
	}
	return transfer.Peer{
		ConnID:      transfer.ConnID(co.connID),
		PackageID:   co.caller.PackageID,
		ComponentID: co.caller.ComponentID,
		Credential: transfer.PeerCredential{
			PID: co.caller.PID,
			UID: co.caller.UID,
			GID: co.caller.GID,
		},
	}
}
