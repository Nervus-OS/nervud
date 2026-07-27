package protocheck

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

const (
	// DefaultMessageBytes is the kernel fallback when MethodMeta does not
	// declare a request or response quota.
	DefaultMessageBytes = 16 << 10

	// AbsoluteMessageBytes is the control-plane frame hard ceiling. The
	// enclosing Envelope still needs its own size check.
	AbsoluteMessageBytes = 128 << 10

	// MaxMessageDepth bounds both protobuf decoding and the recursive semantic
	// walk. Root messages count as depth one.
	MaxMessageDepth = 64

	// MaxTransferHandles bounds credential extraction independently of message
	// bytes. Route-specific TransferPolicy limits may tighten this later.
	MaxTransferHandles = 32
)

var (
	ErrDescriptorMismatch     = errors.New("protocheck: descriptor does not match method metadata")
	ErrUnexpectedPayload      = errors.New("protocheck: payload is forbidden for an empty type")
	ErrMessageTooLarge        = errors.New("protocheck: message exceeds method quota")
	ErrMalformedMessage       = errors.New("protocheck: malformed protobuf message")
	ErrUnknownFields          = errors.New("protocheck: protobuf message contains unknown fields")
	ErrUnknownEnum            = errors.New("protocheck: protobuf message contains an unknown enum value")
	ErrUninitializedMessage   = errors.New("protocheck: protobuf message is not initialized")
	ErrRecursionLimit         = errors.New("protocheck: protobuf message exceeds recursion limit")
	ErrTooManyTransferHandles = errors.New("protocheck: response contains too many transfer handles")
	ErrInvalidTransferHandle  = errors.New("protocheck: response contains an invalid transfer handle")
)

var (
	officialTransferHandleDescriptor = (&ipcv1.TransferHandle{}).ProtoReflect().Descriptor()
	officialTransferHandleProto      = protodesc.ToDescriptorProto(officialTransferHandleDescriptor)
)

// SuccessResult is a canonical Provider success payload plus every genuine,
// recursively nested nervus.ipc.v1.TransferHandle found in that typed value.
type SuccessResult struct {
	Payload         []byte
	TransferHandles []*ipcv1.TransferHandle
}

// ValidateRequest checks a method request and returns deterministic protobuf
// bytes. The returned slice never aliases wire.
func ValidateRequest(meta *ipcv1.MethodMeta, descriptor protoreflect.MessageDescriptor, wire []byte) ([]byte, error) {
	if meta == nil {
		return nil, ErrNilMethodMeta
	}
	result, err := validatePayload(
		"request",
		meta.GetRequestType(),
		descriptor,
		wire,
		effectiveLimit(meta.GetMaxRequestBytes()),
		false,
	)
	if err != nil {
		return nil, err
	}
	return result.canonical, nil
}

// ValidateSuccess checks a method success payload, returns deterministic
// protobuf bytes, and extracts only fields whose descriptor is the real IPC
// TransferHandle type. Arbitrary bytes, Any values, and look-alike messages are
// never interpreted as credentials.
func ValidateSuccess(meta *ipcv1.MethodMeta, descriptor protoreflect.MessageDescriptor, wire []byte) (SuccessResult, error) {
	if meta == nil {
		return SuccessResult{}, ErrNilMethodMeta
	}
	result, err := validatePayload(
		"success",
		meta.GetResponseType(),
		descriptor,
		wire,
		effectiveLimit(meta.GetMaxResponseBytes()),
		true,
	)
	if err != nil {
		return SuccessResult{}, err
	}
	return SuccessResult{
		Payload:         result.canonical,
		TransferHandles: result.handles,
	}, nil
}

// ValidateFailureDetail structurally checks and canonicalizes typed
// Failure.error_detail bytes.
//
// This function does not authorize a (StatusCode, domain reason) pair: the
// current IPC schema has no machine-readable mapping for that relationship.
// Callers must apply a separate mapping policy before forwarding a non-empty
// detail.
func ValidateFailureDetail(meta *ipcv1.MethodMeta, descriptor protoreflect.MessageDescriptor, wire []byte) ([]byte, error) {
	if meta == nil {
		return nil, ErrNilMethodMeta
	}
	result, err := validatePayload(
		"failure detail",
		meta.GetErrorDetailType(),
		descriptor,
		wire,
		effectiveLimit(meta.GetMaxResponseBytes()),
		false,
	)
	if err != nil {
		return nil, err
	}
	return result.canonical, nil
}

type validationResult struct {
	canonical []byte
	handles   []*ipcv1.TransferHandle
}

func validatePayload(
	label string,
	expectedType string,
	descriptor protoreflect.MessageDescriptor,
	wire []byte,
	limit int,
	extractTransfers bool,
) (validationResult, error) {
	if expectedType == "" {
		if descriptor != nil {
			return validationResult{}, fmt.Errorf(
				"%w: %s has no declared type but descriptor is %q",
				ErrDescriptorMismatch, label, descriptor.FullName(),
			)
		}
		if len(wire) != 0 {
			return validationResult{}, fmt.Errorf(
				"%w: %s has %d bytes", ErrUnexpectedPayload, label, len(wire),
			)
		}
		return validationResult{}, nil
	}

	if descriptor == nil || string(descriptor.FullName()) != expectedType {
		actual := "<nil>"
		if descriptor != nil {
			actual = string(descriptor.FullName())
		}
		return validationResult{}, fmt.Errorf(
			"%w: %s wants %q, got %q",
			ErrDescriptorMismatch, label, expectedType, actual,
		)
	}
	if len(wire) > limit {
		return validationResult{}, fmt.Errorf(
			"%w: %s has %d bytes, limit %d",
			ErrMessageTooLarge, label, len(wire), limit,
		)
	}

	message := dynamicpb.NewMessage(descriptor)
	if err := (proto.UnmarshalOptions{
		DiscardUnknown: false,
		AllowPartial:   true,
		RecursionLimit: MaxMessageDepth + 8,
	}).Unmarshal(wire, message); err != nil {
		return validationResult{}, fmt.Errorf("%w: %s: %v", ErrMalformedMessage, label, err)
	}
	if err := validateWireFields(wire, descriptor, "$", 1); err != nil {
		return validationResult{}, err
	}
	if err := proto.CheckInitialized(message); err != nil {
		return validationResult{}, fmt.Errorf("%w: %s: %v", ErrUninitializedMessage, label, err)
	}

	state := walkState{extractTransfers: extractTransfers}
	if err := walkMessage(message.ProtoReflect(), "$", 1, &state); err != nil {
		return validationResult{}, err
	}

	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return validationResult{}, fmt.Errorf("%w: canonicalize %s: %v", ErrMalformedMessage, label, err)
	}
	if len(canonical) > limit {
		return validationResult{}, fmt.Errorf(
			"%w: canonical %s has %d bytes, limit %d",
			ErrMessageTooLarge, label, len(canonical), limit,
		)
	}

	return validationResult{canonical: canonical, handles: state.handles}, nil
}

// validateWireFields runs in addition to the reflection walk below. The Go
// protobuf decoder intentionally discards unknown fields from synthetic map
// entry messages, so Message.GetUnknown alone cannot enforce the kernel's
// reject-unknown contract for every nested wire message.
func validateWireFields(
	wire []byte,
	descriptor protoreflect.MessageDescriptor,
	path string,
	depth int,
) error {
	if depth > MaxMessageDepth {
		return fmt.Errorf("%w: %s depth=%d", ErrRecursionLimit, path, depth)
	}

	for len(wire) != 0 {
		number, wireType, tagBytes := protowire.ConsumeTag(wire)
		if tagBytes < 0 {
			return fmt.Errorf(
				"%w: %s: %v",
				ErrMalformedMessage,
				path,
				protowire.ParseError(tagBytes),
			)
		}
		wire = wire[tagBytes:]

		field := descriptor.Fields().ByNumber(protoreflect.FieldNumber(number))
		if field == nil {
			return fmt.Errorf("%w: %s field=%d", ErrUnknownFields, path, number)
		}
		fieldPath := path + "." + string(field.Name())
		if !fieldAcceptsWireType(field, wireType) {
			return fmt.Errorf(
				"%w: %s uses wire type %d",
				ErrMalformedMessage,
				fieldPath,
				wireType,
			)
		}

		var valueBytes int
		switch {
		case field.Kind() == protoreflect.EnumKind && wireType == protowire.VarintType:
			number, consumed := protowire.ConsumeVarint(wire)
			if consumed < 0 {
				return fmt.Errorf(
					"%w: %s: %v",
					ErrMalformedMessage,
					fieldPath,
					protowire.ParseError(consumed),
				)
			}
			if err := validateEnumNumber(field, number, fieldPath); err != nil {
				return err
			}
			valueBytes = consumed
		case field.Kind() == protoreflect.EnumKind && wireType == protowire.BytesType:
			packed, consumed := protowire.ConsumeBytes(wire)
			if consumed < 0 {
				return fmt.Errorf(
					"%w: %s: %v",
					ErrMalformedMessage,
					fieldPath,
					protowire.ParseError(consumed),
				)
			}
			for index := 0; len(packed) != 0; index++ {
				number, enumBytes := protowire.ConsumeVarint(packed)
				if enumBytes < 0 {
					return fmt.Errorf(
						"%w: %s[%d]: %v",
						ErrMalformedMessage,
						fieldPath,
						index,
						protowire.ParseError(enumBytes),
					)
				}
				if err := validateEnumNumber(
					field,
					number,
					fmt.Sprintf("%s[%d]", fieldPath, index),
				); err != nil {
					return err
				}
				packed = packed[enumBytes:]
			}
			valueBytes = consumed
		case wireType == protowire.BytesType:
			value, consumed := protowire.ConsumeBytes(wire)
			if consumed < 0 {
				return fmt.Errorf(
					"%w: %s: %v",
					ErrMalformedMessage,
					fieldPath,
					protowire.ParseError(consumed),
				)
			}
			if field.Kind() == protoreflect.MessageKind {
				if err := validateWireFields(
					value,
					field.Message(),
					fieldPath,
					depth+1,
				); err != nil {
					return err
				}
			}
			valueBytes = consumed
		case wireType == protowire.StartGroupType:
			value, consumed := protowire.ConsumeGroup(number, wire)
			if consumed < 0 {
				return fmt.Errorf(
					"%w: %s: %v",
					ErrMalformedMessage,
					fieldPath,
					protowire.ParseError(consumed),
				)
			}
			if err := validateWireFields(
				value,
				field.Message(),
				fieldPath,
				depth+1,
			); err != nil {
				return err
			}
			valueBytes = consumed
		default:
			valueBytes = protowire.ConsumeFieldValue(number, wireType, wire)
			if valueBytes < 0 {
				return fmt.Errorf(
					"%w: %s: %v",
					ErrMalformedMessage,
					fieldPath,
					protowire.ParseError(valueBytes),
				)
			}
		}
		wire = wire[valueBytes:]
	}
	return nil
}

func validateEnumNumber(
	field protoreflect.FieldDescriptor,
	wireNumber uint64,
	path string,
) error {
	number := protoreflect.EnumNumber(wireNumber)
	if uint64(number) != wireNumber {
		return fmt.Errorf("%w: %s=%d", ErrUnknownEnum, path, wireNumber)
	}
	if field.Enum().Values().ByNumber(number) == nil {
		return fmt.Errorf("%w: %s=%d", ErrUnknownEnum, path, number)
	}
	return nil
}

func fieldAcceptsWireType(field protoreflect.FieldDescriptor, wireType protowire.Type) bool {
	switch field.Kind() {
	case protoreflect.BoolKind,
		protoreflect.EnumKind,
		protoreflect.Int32Kind,
		protoreflect.Sint32Kind,
		protoreflect.Uint32Kind,
		protoreflect.Int64Kind,
		protoreflect.Sint64Kind,
		protoreflect.Uint64Kind:
		return wireType == protowire.VarintType ||
			(field.IsList() && wireType == protowire.BytesType)
	case protoreflect.Sfixed32Kind,
		protoreflect.Fixed32Kind,
		protoreflect.FloatKind:
		return wireType == protowire.Fixed32Type ||
			(field.IsList() && wireType == protowire.BytesType)
	case protoreflect.Sfixed64Kind,
		protoreflect.Fixed64Kind,
		protoreflect.DoubleKind:
		return wireType == protowire.Fixed64Type ||
			(field.IsList() && wireType == protowire.BytesType)
	case protoreflect.StringKind,
		protoreflect.BytesKind,
		protoreflect.MessageKind:
		return wireType == protowire.BytesType
	case protoreflect.GroupKind:
		return wireType == protowire.StartGroupType
	default:
		return false
	}
}

type walkState struct {
	extractTransfers bool
	handles          []*ipcv1.TransferHandle
}

func walkMessage(message protoreflect.Message, path string, depth int, state *walkState) error {
	if depth > MaxMessageDepth {
		return fmt.Errorf("%w: %s depth=%d", ErrRecursionLimit, path, depth)
	}
	if len(message.GetUnknown()) != 0 {
		return fmt.Errorf("%w: %s", ErrUnknownFields, path)
	}

	fields := message.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		if !message.Has(field) {
			continue
		}
		value := message.Get(field)
		fieldPath := path + "." + string(field.Name())
		switch {
		case field.IsMap():
			valueDescriptor := field.MapValue()
			var walkErr error
			value.Map().Range(func(key protoreflect.MapKey, mapValue protoreflect.Value) bool {
				walkErr = walkValue(
					valueDescriptor,
					mapValue,
					fmt.Sprintf("%s[%v]", fieldPath, key.Interface()),
					depth,
					state,
				)
				return walkErr == nil
			})
			if walkErr != nil {
				return walkErr
			}
		case field.IsList():
			list := value.List()
			for item := 0; item < list.Len(); item++ {
				if err := walkValue(
					field,
					list.Get(item),
					fmt.Sprintf("%s[%d]", fieldPath, item),
					depth,
					state,
				); err != nil {
					return err
				}
			}
		default:
			if err := walkValue(field, value, fieldPath, depth, state); err != nil {
				return err
			}
		}
	}

	if state.extractTransfers && isTransferHandleDescriptor(message.Descriptor()) {
		if len(state.handles) >= MaxTransferHandles {
			return fmt.Errorf("%w: limit %d", ErrTooManyTransferHandles, MaxTransferHandles)
		}
		handle, err := copyTransferHandle(message)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidTransferHandle, path, err)
		}
		state.handles = append(state.handles, handle)
	}
	return nil
}

func walkValue(
	descriptor protoreflect.FieldDescriptor,
	value protoreflect.Value,
	path string,
	parentDepth int,
	state *walkState,
) error {
	switch descriptor.Kind() {
	case protoreflect.EnumKind:
		number := value.Enum()
		if descriptor.Enum().Values().ByNumber(number) == nil {
			return fmt.Errorf("%w: %s=%d", ErrUnknownEnum, path, number)
		}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return walkMessage(value.Message(), path, parentDepth+1, state)
	}
	return nil
}

func isTransferHandleDescriptor(descriptor protoreflect.MessageDescriptor) bool {
	if descriptor == nil ||
		descriptor.FullName() != officialTransferHandleDescriptor.FullName() ||
		descriptor.ParentFile().Path() != officialTransferHandleDescriptor.ParentFile().Path() {
		return false
	}
	return proto.Equal(protodesc.ToDescriptorProto(descriptor), officialTransferHandleProto)
}

func copyTransferHandle(message protoreflect.Message) (*ipcv1.TransferHandle, error) {
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message.Interface())
	if err != nil {
		return nil, err
	}
	var handle ipcv1.TransferHandle
	if err := proto.Unmarshal(wire, &handle); err != nil {
		return nil, err
	}
	if len(handle.GetTransferId()) != 16 {
		return nil, fmt.Errorf("transfer_id has %d bytes, want 16", len(handle.GetTransferId()))
	}
	if len(handle.GetAttachTicket()) < 32 {
		return nil, fmt.Errorf("attach_ticket has %d bytes, want at least 32", len(handle.GetAttachTicket()))
	}
	switch handle.GetRole() {
	case ipcv1.TransferRole_TRANSFER_ROLE_PRODUCER,
		ipcv1.TransferRole_TRANSFER_ROLE_CONSUMER,
		ipcv1.TransferRole_TRANSFER_ROLE_PEER:
	default:
		return nil, fmt.Errorf("invalid role %d", handle.GetRole())
	}
	switch handle.GetMode() {
	case ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY,
		ipcv1.TransferMode_TRANSFER_MODE_SHARED_MEMORY_RING:
	default:
		return nil, fmt.Errorf("invalid mode %d", handle.GetMode())
	}
	if handle.GetExpiresAtMonotonicNanos() == 0 {
		return nil, errors.New("zero monotonic expiry")
	}
	if handle.GetDataPlaneEndpoint() == "" {
		return nil, errors.New("empty data-plane endpoint")
	}
	return &handle, nil
}

func effectiveLimit(declared uint32) int {
	if declared == 0 {
		return DefaultMessageBytes
	}
	if declared > AbsoluteMessageBytes {
		return AbsoluteMessageBytes
	}
	return int(declared)
}
