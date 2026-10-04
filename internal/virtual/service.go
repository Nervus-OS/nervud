package virtual

import (
	"fmt"
	"log/slog"
	"nervud/internal/registry"

	pb "github.com/Nervus-OS/nervus-ipc/go/v2"
)

const VirtualServiceID = "nervud.system.server"

type Service struct {
	componentStore *registry.ComponentStore
}

func NewService(store *registry.ComponentStore) *Service {
	return &Service{
		componentStore: store,
	}
}

// HandleRequest handles socket request to the virtual service
func (s *Service) HandleRequest(req *pb.Request, callerUID uint32) *pb.Response {
	slog.Debug("virtual service request",
		"method", req.Method,
		"requestID", req.RequestId,
		"callerUID", callerUID,
		"target", req.TargetService)

	defer func() {
		if r := recover(); r != nil {
			slog.Error("virtual service panic",
				"method", req.Method,
				"requestID", req.RequestId,
				"panic", r)
		}
	}()

	// Handle request based on method
	switch req.Method {
	// TODO: Implement the following methods in the virtual service

	default:
		slog.Warn("unknown virtual service method",
			"method", req.Method,
			"requestID", req.RequestId)
		return ErrorResponse(req.RequestId,
			pb.StatusCode_STATUS_CODE_NOT_FOUND,
			fmt.Sprintf("method not found: %s", req.Method))
	}
}

// IsVirtualService checks if the target service is the virtual service
func IsVirtualService(targetService string) bool {
	return targetService == VirtualServiceID
}
