package virtual

import (
	"encoding/json"
	"log/slog"
	"slices"

	pb "github.com/Nervus-OS/nervus-ipc/go/v2"
)

// ErrorResponse Construct an error response
func ErrorResponse(requestID string, code pb.StatusCode, message string) *pb.Response {
	return &pb.Response{
		RequestId: requestID,
		Outcome: &pb.Response_Failure{
			Failure: &pb.Failure{
				Code:          code,
				PublicMessage: message,
			},
		},
	}
}

// SuccessResponse Construct a successful response
// payload will be serialized as JSON and placed in Response.Success.Payload
func SuccessResponse(requestID string, payload any) *pb.Response {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("marshal response payload failed", "error", err)
		return &pb.Response{
			RequestId: requestID,
			Outcome: &pb.Response_Failure{
				Failure: &pb.Failure{
					Code:          pb.StatusCode_STATUS_CODE_INTERNAL,
					PublicMessage: "failed to serialize response",
				},
			},
		}
	}

	return &pb.Response{
		RequestId: requestID,
		Outcome: &pb.Response_Success{
			Success: &pb.Success{
				Code:    pb.StatusCode_STATUS_CODE_OK,
				Payload: data,
			},
		},
	}
}

// AcceptedResponse Construct an accepted response (for asynchronous)
func AcceptedResponse(requestID string, payload any) *pb.Response {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("marshal response payload failed", "error", err)
		return ErrorResponse(requestID,
			pb.StatusCode_STATUS_CODE_INTERNAL,
			"failed to serialize response")
	}

	return &pb.Response{
		RequestId: requestID,
		Outcome: &pb.Response_Success{
			Success: &pb.Success{
				Code:    pb.StatusCode_STATUS_CODE_ACCEPTED,
				Payload: data,
			},
		},
	}
}

// HasPermission checks if the permissions list contains the specified permission
func HasPermission(permissions []string, required string) bool {
	return slices.Contains(permissions, required)
}
