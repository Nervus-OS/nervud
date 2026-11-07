package virtual

import (
	"encoding/json"
	"log/slog"
	"nervud/internal/helpers"
	"nervud/internal/registry"

	pb "github.com/Nervus-OS/nervus-ipc/go/v2"
)

type executeComponentRequest struct {
	ComponentID string `json:"component_id"`
	Arg         string `json:"arg"`
}

// handleExecuteComponent Execute Component
func (s *Service) handleExecuteComponent(req *pb.Request, callerUID uint32) *pb.Response {
	var params executeComponentRequest
	if err := json.Unmarshal(req.Payload, &params); err != nil {
		return ErrorResponse(req.RequestId, pb.StatusCode_STATUS_CODE_INVALID_ARGUMENT, "invalid payload")
	}

	caller, exists := registry.GetComponentByUID(int32(callerUID))
	if !exists {
		return ErrorResponse(req.RequestId, pb.StatusCode_STATUS_CODE_UNAUTHENTICATED, "unknown caller")
	}

	target, exists := registry.GetComponent(params.ComponentID)
	if !exists {
		return ErrorResponse(req.RequestId, pb.StatusCode_STATUS_CODE_NOT_FOUND, "component not found")
	}
	if !target.IsAvailable {
		return ErrorResponse(req.RequestId, pb.StatusCode_STATUS_CODE_UNAVAILABLE, "component unavailable")
	}

	// Components of the same package always reach each other
	// 同包组件之间始终放行
	if !registry.SamePackage(caller.ID, target.ID) &&
		!registry.HasPermission(caller.ID, registry.PermSystemComponentExecute) &&
		!registry.HasPermission(caller.ID, registry.PermComponentExecute) {
		return ErrorResponse(req.RequestId, pb.StatusCode_STATUS_CODE_PERMISSION_DENIED, "permission denied")
	}

	if err := helpers.ExecuteComponent(target, params.Arg); err != nil {
		slog.Error("execute component failed", "component", target.ID, "error", err)
		return ErrorResponse(req.RequestId, pb.StatusCode_STATUS_CODE_FAILED_PRECONDITION, err.Error())
	}
	return SuccessResponse(req.RequestId, nil)
}
