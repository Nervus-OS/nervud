package protocheck

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	safetyv1 "github.com/nervus-os/nervus-ipc/protocol/interface/safetyv1"
	transferv1 "github.com/nervus-os/nervus-ipc/protocol/interface/transferv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

func TestValidateRequestCanonicalizes(t *testing.T) {
	t.Parallel()

	descriptor := (&ipcv1.Ping{}).ProtoReflect().Descriptor()
	meta := requestMeta(descriptor, DefaultMessageBytes)

	var wire []byte
	wire = protowire.AppendTag(wire, 1, protowire.VarintType)
	wire = protowire.AppendVarint(wire, 1)
	wire = protowire.AppendTag(wire, 1, protowire.VarintType)
	wire = protowire.AppendVarint(wire, 2)

	got, err := ValidateRequest(meta, descriptor, wire)
	if err != nil {
		t.Fatalf("ValidateRequest() error = %v", err)
	}
	want, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&ipcv1.Ping{Nonce: 2})
	if err != nil {
		t.Fatalf("marshal expected Ping: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes = %x, want %x", got, want)
	}

	wire[0] ^= 0xff
	if !bytes.Equal(got, want) {
		t.Fatal("canonical result aliases the input wire")
	}
}

func TestValidateRequestRejectsInvalidStructure(t *testing.T) {
	t.Parallel()

	pingDescriptor := (&ipcv1.Ping{}).ProtoReflect().Descriptor()
	meta := requestMeta(pingDescriptor, DefaultMessageBytes)

	unknown := mustMarshal(t, &ipcv1.Ping{Nonce: 1})
	unknown = protowire.AppendTag(unknown, 99, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)

	tests := []struct {
		name       string
		meta       *ipcv1.MethodMeta
		descriptor protoreflect.MessageDescriptor
		wire       []byte
		want       error
	}{
		{
			name: "nil metadata",
			want: ErrNilMethodMeta,
		},
		{
			name: "unknown field",
			meta: meta, descriptor: pingDescriptor, wire: unknown,
			want: ErrUnknownFields,
		},
		{
			name: "malformed wire",
			meta: meta, descriptor: pingDescriptor, wire: []byte{0xff},
			want: ErrMalformedMessage,
		},
		{
			name:       "descriptor mismatch",
			meta:       meta,
			descriptor: (&ipcv1.Pong{}).ProtoReflect().Descriptor(),
			want:       ErrDescriptorMismatch,
		},
		{
			name: "empty type with payload",
			meta: &ipcv1.MethodMeta{}, wire: []byte{1},
			want: ErrUnexpectedPayload,
		},
		{
			name: "empty type with descriptor",
			meta: &ipcv1.MethodMeta{}, descriptor: pingDescriptor,
			want: ErrDescriptorMismatch,
		},
		{
			name:       "method quota",
			meta:       requestMeta(pingDescriptor, 1),
			descriptor: pingDescriptor,
			wire:       mustMarshal(t, &ipcv1.Ping{Nonce: 1}),
			want:       ErrMessageTooLarge,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateRequest(test.meta, test.descriptor, test.wire)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateRequest() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateRequestRejectsUninitializedProto2(t *testing.T) {
	t.Parallel()

	descriptor := requiredMessageDescriptor(t)
	meta := requestMeta(descriptor, DefaultMessageBytes)
	_, err := ValidateRequest(meta, descriptor, nil)
	if !errors.Is(err, ErrUninitializedMessage) {
		t.Fatalf("ValidateRequest() error = %v, want %v", err, ErrUninitializedMessage)
	}
}

func TestValidateRequestRejectsExcessiveDepth(t *testing.T) {
	t.Parallel()

	descriptor := recursiveMessageDescriptor(t)
	meta := requestMeta(descriptor, DefaultMessageBytes)

	var wire []byte
	for i := 0; i < MaxMessageDepth; i++ {
		var outer []byte
		outer = protowire.AppendTag(outer, 1, protowire.BytesType)
		outer = protowire.AppendBytes(outer, wire)
		wire = outer
	}

	_, err := ValidateRequest(meta, descriptor, wire)
	if !errors.Is(err, ErrRecursionLimit) {
		t.Fatalf("ValidateRequest() error = %v, want %v", err, ErrRecursionLimit)
	}
}

func TestValidateRequestRejectsUnknownMapEntryField(t *testing.T) {
	t.Parallel()

	descriptor := mapHolderDescriptor(t)
	meta := requestMeta(descriptor, DefaultMessageBytes)

	var entry []byte
	entry = protowire.AppendTag(entry, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, "camera")
	entry = protowire.AppendTag(entry, 2, protowire.BytesType)
	entry = protowire.AppendString(entry, "front")
	entry = protowire.AppendTag(entry, 99, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 1)

	_, err := ValidateRequest(meta, descriptor, appendMessageField(nil, 1, entry))
	if !errors.Is(err, ErrUnknownFields) {
		t.Fatalf("ValidateRequest() error = %v, want %v", err, ErrUnknownFields)
	}
}

func TestValidateRequestRejectsUnknownMapEnum(t *testing.T) {
	t.Parallel()

	descriptor := enumMapHolderDescriptor(t)
	meta := requestMeta(descriptor, DefaultMessageBytes)

	var entry []byte
	entry = protowire.AppendTag(entry, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, "camera")
	entry = protowire.AppendTag(entry, 2, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 99)

	_, err := ValidateRequest(meta, descriptor, appendMessageField(nil, 1, entry))
	if !errors.Is(err, ErrUnknownEnum) {
		t.Fatalf("ValidateRequest() error = %v, want %v", err, ErrUnknownEnum)
	}
}

func TestValidateSuccessRejectsNestedUnknownAndUnknownEnum(t *testing.T) {
	t.Parallel()

	descriptor := (&transferv1.BeginTransferResponse{}).ProtoReflect().Descriptor()
	meta := responseMeta(descriptor, DefaultMessageBytes)

	withUnknown := validTransferHandle(1, ipcv1.TransferRole_TRANSFER_ROLE_PRODUCER)
	unknown := protowire.AppendTag(nil, 99, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)
	withUnknown.ProtoReflect().SetUnknown(unknown)

	unknownWire := mustMarshal(t, &transferv1.BeginTransferResponse{Provider: withUnknown})
	_, err := ValidateSuccess(meta, descriptor, unknownWire)
	if !errors.Is(err, ErrUnknownFields) {
		t.Fatalf("nested unknown error = %v, want %v", err, ErrUnknownFields)
	}

	unknownEnum := validTransferHandle(2, ipcv1.TransferRole(99))
	enumWire := mustMarshal(t, &transferv1.BeginTransferResponse{Provider: unknownEnum})
	_, err = ValidateSuccess(meta, descriptor, enumWire)
	if !errors.Is(err, ErrUnknownEnum) {
		t.Fatalf("unknown enum error = %v, want %v", err, ErrUnknownEnum)
	}
}

func TestValidateSuccessExtractsOnlyTypedTransferHandles(t *testing.T) {
	t.Parallel()

	directDescriptor := (&transferv1.BeginTransferResponse{}).ProtoReflect().Descriptor()
	directMeta := responseMeta(directDescriptor, DefaultMessageBytes)
	provider := validTransferHandle(3, ipcv1.TransferRole_TRANSFER_ROLE_PRODUCER)
	caller := validTransferHandle(4, ipcv1.TransferRole_TRANSFER_ROLE_CONSUMER)

	result, err := ValidateSuccess(
		directMeta,
		directDescriptor,
		mustMarshal(t, &transferv1.BeginTransferResponse{Provider: provider, Caller: caller}),
	)
	if err != nil {
		t.Fatalf("ValidateSuccess(direct) error = %v", err)
	}
	if len(result.TransferHandles) != 2 {
		t.Fatalf("direct handle count = %d, want 2", len(result.TransferHandles))
	}
	if !proto.Equal(result.TransferHandles[0], provider) || !proto.Equal(result.TransferHandles[1], caller) {
		t.Fatalf("extracted direct handles = %#v", result.TransferHandles)
	}

	nestedDescriptor := nestedTransferDescriptor(t)
	nestedMeta := responseMeta(nestedDescriptor, DefaultMessageBytes)
	handleWire := mustMarshal(t, caller)
	innerWire := appendMessageField(nil, 1, handleWire)
	outerWire := appendMessageField(nil, 1, innerWire)

	result, err = ValidateSuccess(nestedMeta, nestedDescriptor, outerWire)
	if err != nil {
		t.Fatalf("ValidateSuccess(nested) error = %v", err)
	}
	if len(result.TransferHandles) != 1 || !proto.Equal(result.TransferHandles[0], caller) {
		t.Fatalf("nested handles = %#v, want caller handle", result.TransferHandles)
	}

	bytesDescriptor := bytesHolderDescriptor(t)
	bytesMeta := responseMeta(bytesDescriptor, DefaultMessageBytes)
	bytesWire := appendMessageField(nil, 1, handleWire)
	result, err = ValidateSuccess(bytesMeta, bytesDescriptor, bytesWire)
	if err != nil {
		t.Fatalf("ValidateSuccess(bytes look-alike) error = %v", err)
	}
	if len(result.TransferHandles) != 0 {
		t.Fatalf("bytes look-alike yielded %d handles, want 0", len(result.TransferHandles))
	}

	lookalikeDescriptor := lookalikeTransferDescriptor(t)
	lookalikeMeta := responseMeta(lookalikeDescriptor, DefaultMessageBytes)
	result, err = ValidateSuccess(lookalikeMeta, lookalikeDescriptor, handleWire)
	if err != nil {
		t.Fatalf("ValidateSuccess(message look-alike) error = %v", err)
	}
	if len(result.TransferHandles) != 0 {
		t.Fatalf("message look-alike yielded %d handles, want 0", len(result.TransferHandles))
	}
}

func TestValidateSuccessRejectsInvalidOrExcessiveTransferHandles(t *testing.T) {
	t.Parallel()

	directDescriptor := (&transferv1.BeginTransferResponse{}).ProtoReflect().Descriptor()
	directMeta := responseMeta(directDescriptor, DefaultMessageBytes)
	invalid := validTransferHandle(5, ipcv1.TransferRole_TRANSFER_ROLE_CONSUMER)
	invalid.TransferId = []byte{1}

	_, err := ValidateSuccess(
		directMeta,
		directDescriptor,
		mustMarshal(t, &transferv1.BeginTransferResponse{Caller: invalid}),
	)
	if !errors.Is(err, ErrInvalidTransferHandle) {
		t.Fatalf("invalid handle error = %v, want %v", err, ErrInvalidTransferHandle)
	}

	repeatedDescriptor := repeatedTransferDescriptor(t)
	repeatedMeta := responseMeta(repeatedDescriptor, AbsoluteMessageBytes)
	handleWire := mustMarshal(t, validTransferHandle(6, ipcv1.TransferRole_TRANSFER_ROLE_CONSUMER))
	var repeatedWire []byte
	for i := 0; i < MaxTransferHandles+1; i++ {
		repeatedWire = appendMessageField(repeatedWire, 1, handleWire)
	}

	_, err = ValidateSuccess(repeatedMeta, repeatedDescriptor, repeatedWire)
	if !errors.Is(err, ErrTooManyTransferHandles) {
		t.Fatalf("excessive handles error = %v, want %v", err, ErrTooManyTransferHandles)
	}
}

func TestValidateFailureDetail(t *testing.T) {
	t.Parallel()

	descriptor := (&safetyv1.SafetyControlErrorDetail{}).ProtoReflect().Descriptor()
	meta := &ipcv1.MethodMeta{
		ErrorDetailType:  string(descriptor.FullName()),
		MaxResponseBytes: DefaultMessageBytes,
	}

	var wire []byte
	wire = protowire.AppendTag(wire, 1, protowire.VarintType)
	wire = protowire.AppendVarint(wire, uint64(safetyv1.SafetyControlReason_SAFETY_CONTROL_REASON_STOP_NOT_SETTLED))
	wire = protowire.AppendTag(wire, 1, protowire.VarintType)
	wire = protowire.AppendVarint(wire, uint64(safetyv1.SafetyControlReason_SAFETY_CONTROL_REASON_WRONG_STATE))

	got, err := ValidateFailureDetail(meta, descriptor, wire)
	if err != nil {
		t.Fatalf("ValidateFailureDetail() error = %v", err)
	}
	want := mustMarshal(t, &safetyv1.SafetyControlErrorDetail{
		Reason: safetyv1.SafetyControlReason_SAFETY_CONTROL_REASON_WRONG_STATE,
	})
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical detail = %x, want %x", got, want)
	}

	unknownEnum := &safetyv1.SafetyControlErrorDetail{Reason: safetyv1.SafetyControlReason(999)}
	_, err = ValidateFailureDetail(meta, descriptor, mustMarshal(t, unknownEnum))
	if !errors.Is(err, ErrUnknownEnum) {
		t.Fatalf("unknown detail enum error = %v, want %v", err, ErrUnknownEnum)
	}

	var wrappedEnum []byte
	wrappedEnum = protowire.AppendTag(wrappedEnum, 1, protowire.VarintType)
	wrappedEnum = protowire.AppendVarint(
		wrappedEnum,
		uint64(safetyv1.SafetyControlReason_SAFETY_CONTROL_REASON_WRONG_STATE)+(1<<32),
	)
	_, err = ValidateFailureDetail(meta, descriptor, wrappedEnum)
	if !errors.Is(err, ErrUnknownEnum) {
		t.Fatalf("wrapped detail enum error = %v, want %v", err, ErrUnknownEnum)
	}

	_, err = ValidateFailureDetail(&ipcv1.MethodMeta{}, nil, []byte{1})
	if !errors.Is(err, ErrUnexpectedPayload) {
		t.Fatalf("detail without type error = %v, want %v", err, ErrUnexpectedPayload)
	}
}

func TestEmptySuccessType(t *testing.T) {
	t.Parallel()

	result, err := ValidateSuccess(&ipcv1.MethodMeta{}, nil, nil)
	if err != nil {
		t.Fatalf("ValidateSuccess(empty) error = %v", err)
	}
	if len(result.Payload) != 0 || len(result.TransferHandles) != 0 {
		t.Fatalf("ValidateSuccess(empty) = %#v", result)
	}

	_, err = ValidateSuccess(&ipcv1.MethodMeta{}, nil, []byte{1})
	if !errors.Is(err, ErrUnexpectedPayload) {
		t.Fatalf("non-empty success error = %v, want %v", err, ErrUnexpectedPayload)
	}
}

func requestMeta(descriptor protoreflect.MessageDescriptor, max uint32) *ipcv1.MethodMeta {
	return &ipcv1.MethodMeta{
		RequestType:     string(descriptor.FullName()),
		MaxRequestBytes: max,
	}
}

func responseMeta(descriptor protoreflect.MessageDescriptor, max uint32) *ipcv1.MethodMeta {
	return &ipcv1.MethodMeta{
		ResponseType:     string(descriptor.FullName()),
		MaxResponseBytes: max,
	}
}

func mustMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	wire, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("marshal %T: %v", message, err)
	}
	return wire
}

func appendMessageField(dst []byte, number protowire.Number, wire []byte) []byte {
	dst = protowire.AppendTag(dst, number, protowire.BytesType)
	return protowire.AppendBytes(dst, wire)
}

func validTransferHandle(seed byte, role ipcv1.TransferRole) *ipcv1.TransferHandle {
	return &ipcv1.TransferHandle{
		TransferId:              bytes.Repeat([]byte{seed}, 16),
		AttachTicket:            bytes.Repeat([]byte{seed + 1}, 32),
		Role:                    role,
		Mode:                    ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY,
		ExpiresAtMonotonicNanos: 1,
		DataPlaneEndpoint:       "/run/nervus/nervud-transfer.sock",
	}
}

func requiredMessageDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("protocheck/required.proto"),
		Package: proto.String("protocheck.required"),
		Syntax:  proto.String("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Required"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:   proto.String("value"),
				Number: proto.Int32(1),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_REQUIRED.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			}},
		}},
	}
	return mustMessageDescriptor(t, file, "Required")
}

func recursiveMessageDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("protocheck/recursive.proto"),
		Package: proto.String("protocheck.recursive"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Node"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:     proto.String("child"),
				Number:   proto.Int32(1),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
				TypeName: proto.String(".protocheck.recursive.Node"),
			}},
		}},
	}
	return mustMessageDescriptor(t, file, "Node")
}

func mapHolderDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("protocheck/map_holder.proto"),
		Package: proto.String("protocheck.map"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Holder"),
			Field: []*descriptorpb.FieldDescriptorProto{
				messageField("labels", 1, ".protocheck.map.Holder.LabelsEntry", true),
			},
			NestedType: []*descriptorpb.DescriptorProto{{
				Name: proto.String("LabelsEntry"),
				Field: []*descriptorpb.FieldDescriptorProto{
					scalarField("key", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING),
					scalarField("value", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING),
				},
				Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
			}},
		}},
	}
	return mustMessageDescriptor(t, file, "Holder")
}

func enumMapHolderDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("protocheck/enum_map_holder.proto"),
		Package: proto.String("protocheck.enummap"),
		Syntax:  proto.String("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("State"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("STATE_UNSPECIFIED"), Number: proto.Int32(0)},
				{Name: proto.String("STATE_READY"), Number: proto.Int32(1)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Holder"),
			Field: []*descriptorpb.FieldDescriptorProto{
				messageField("states", 1, ".protocheck.enummap.Holder.StatesEntry", true),
			},
			NestedType: []*descriptorpb.DescriptorProto{{
				Name: proto.String("StatesEntry"),
				Field: []*descriptorpb.FieldDescriptorProto{
					scalarField("key", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING),
					{
						Name:     proto.String("value"),
						Number:   proto.Int32(2),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(),
						TypeName: proto.String(".protocheck.enummap.State"),
					},
				},
				Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
			}},
		}},
	}
	return mustMessageDescriptor(t, file, "Holder")
}

func nestedTransferDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := transferFile("protocheck/nested_transfer.proto", "protocheck.nested")
	file.MessageType = []*descriptorpb.DescriptorProto{
		{
			Name: proto.String("Inner"),
			Field: []*descriptorpb.FieldDescriptorProto{
				messageField("handle", 1, ".nervus.ipc.v1.TransferHandle", false),
			},
		},
		{
			Name: proto.String("Outer"),
			Field: []*descriptorpb.FieldDescriptorProto{
				messageField("inner", 1, ".protocheck.nested.Inner", false),
			},
		},
	}
	return mustMessageDescriptor(t, file, "Outer")
}

func repeatedTransferDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := transferFile("protocheck/repeated_transfer.proto", "protocheck.repeated")
	file.MessageType = []*descriptorpb.DescriptorProto{{
		Name: proto.String("Response"),
		Field: []*descriptorpb.FieldDescriptorProto{
			messageField("handles", 1, ".nervus.ipc.v1.TransferHandle", true),
		},
	}}
	return mustMessageDescriptor(t, file, "Response")
}

func bytesHolderDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("protocheck/bytes_holder.proto"),
		Package: proto.String("protocheck.bytes"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Response"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:   proto.String("payload"),
				Number: proto.Int32(1),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(),
			}},
		}},
	}
	return mustMessageDescriptor(t, file, "Response")
}

func lookalikeTransferDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("protocheck/lookalike_transfer.proto"),
		Package: proto.String("protocheck.lookalike"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("TransferHandle"),
			Field: []*descriptorpb.FieldDescriptorProto{
				scalarField("transfer_id", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES),
				scalarField("attach_ticket", 2, descriptorpb.FieldDescriptorProto_TYPE_BYTES),
				scalarField("role", 3, descriptorpb.FieldDescriptorProto_TYPE_UINT32),
				scalarField("mode", 4, descriptorpb.FieldDescriptorProto_TYPE_UINT32),
				scalarField("expires_at_monotonic_nanos", 5, descriptorpb.FieldDescriptorProto_TYPE_UINT64),
				scalarField("data_plane_endpoint", 6, descriptorpb.FieldDescriptorProto_TYPE_STRING),
			},
		}},
	}
	return mustMessageDescriptor(t, file, "TransferHandle")
}

func transferFile(name, pkg string) *descriptorpb.FileDescriptorProto {
	return &descriptorpb.FileDescriptorProto{
		Name:       proto.String(name),
		Package:    proto.String(pkg),
		Syntax:     proto.String("proto3"),
		Dependency: []string{officialTransferHandleDescriptor.ParentFile().Path()},
	}
}

func messageField(name string, number int32, typeName string, repeated bool) *descriptorpb.FieldDescriptorProto {
	label := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	if repeated {
		label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	}
	return &descriptorpb.FieldDescriptorProto{
		Name:     proto.String(name),
		Number:   proto.Int32(number),
		Label:    label.Enum(),
		Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
		TypeName: proto.String(typeName),
	}
}

func scalarField(
	name string,
	number int32,
	kind descriptorpb.FieldDescriptorProto_Type,
) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:   proto.String(name),
		Number: proto.Int32(number),
		Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		Type:   kind.Enum(),
	}
}

func mustMessageDescriptor(
	t *testing.T,
	file *descriptorpb.FileDescriptorProto,
	name protoreflect.Name,
) protoreflect.MessageDescriptor {
	t.Helper()
	descriptor, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("build descriptor %s: %v", file.GetName(), err)
	}
	message := descriptor.Messages().ByName(name)
	if message == nil {
		t.Fatalf("descriptor %s has no message %s", file.GetName(), name)
	}
	return message
}

func TestErrorMessagesContainFieldPath(t *testing.T) {
	t.Parallel()

	descriptor := (&transferv1.BeginTransferResponse{}).ProtoReflect().Descriptor()
	meta := responseMeta(descriptor, DefaultMessageBytes)
	bad := validTransferHandle(7, ipcv1.TransferRole(99))
	_, err := ValidateSuccess(
		meta,
		descriptor,
		mustMarshal(t, &transferv1.BeginTransferResponse{Caller: bad}),
	)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("$.caller.role")) {
		t.Fatalf("error = %v, want nested field path", err)
	}
}

func ExampleValidateRequest() {
	descriptor := (&ipcv1.Ping{}).ProtoReflect().Descriptor()
	meta := requestMeta(descriptor, 64)
	wire, _ := proto.Marshal(&ipcv1.Ping{Nonce: 42})

	canonical, err := ValidateRequest(meta, descriptor, wire)
	fmt.Println(err == nil, len(canonical) > 0)
	// Output: true true
}
