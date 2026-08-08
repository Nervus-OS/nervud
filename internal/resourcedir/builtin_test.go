package resourcedir

import (
	"testing"

	resourcedirv1 "github.com/nervus-os/nervus-ipc/protocol/interface/resourcedirv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
)

const camType = "nervus.resource.camera"

//

func deviceRegistry(t *testing.T) *catalog.Registry {
	t.Helper()

	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: "nervus.camerad",
		Resources: []*ipcv1.ManagedResource{
			cameraResource("cam.front", map[string]string{
				"nervus.camera.facing": "front", "nervus.camera.class": "hd",
			}),
			cameraResource("cam.front.wide", map[string]string{
				"nervus.camera.facing": "front", "nervus.camera.class": "4k",
			}),
			cameraResource("cam.rear", map[string]string{
				"nervus.camera.facing": "rear",
			}),
			{
				StableRole:   "base.main",
				ResourceType: catalog.ResourceMotionBase,
				AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL,
				RiskClass:    ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			},
		},
	}

	marshal := proto.MarshalOptions{Deterministic: true}
	descriptorWire, err := marshal.Marshal(descriptor)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	schemaWire, err := marshal.Marshal(&ipcv1.InterfaceSchemaBundleSet{})
	if err != nil {
		t.Fatalf("marshal schemas: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("parse artifacts: %v", err)
	}

	registry, err := catalog.NewRegistry([]catalog.Source{{
		PackageID: "nervus.camerad",
		Kind:      catalog.SourceKindSystemImage,
		Trust:     identity.TrustPlatform,
		Signers: catalog.SignerEvidence{
			Roles: []string{"platform-release"},
			VerifiedSigners: []catalog.VerifiedSigner{{
				Role: "platform-release", KeyID: "test-platform-key",
			}},
		},
		Artifacts: artifacts,
	}})
	if err != nil {
		t.Fatalf("catalog NewRegistry: %v", err)
	}
	return registry
}

func cameraResource(role string, labels map[string]string) *ipcv1.ManagedResource {
	return &ipcv1.ManagedResource{
		StableRole:   role,
		ResourceType: camType,
		AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_SHARED_OBSERVE,
		RiskClass:    ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
		Labels:       labels,
	}
}

func list(t *testing.T, m *Module, req *resourcedirv1.ListResourcesRequest) *resourcedirv1.ResourceList {
	t.Helper()
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	result := m.BuiltinHandler()(endpoint.BuiltinCall{
		MethodID: MethodListResources, Payload: payload,
	})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_OK {
		t.Fatalf("code = %v, want OK", result.Code)
	}
	out := &resourcedirv1.ResourceList{}
	if err := proto.Unmarshal(result.Payload, out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return out
}

func roles(out *resourcedirv1.ResourceList) []string {
	got := make([]string, 0, len(out.GetResources()))
	for _, entry := range out.GetResources() {
		got = append(got, entry.GetStableRole())
	}
	return got
}

//

func TestListResources_EmptyRequestListsAll(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	out := list(t, m, &resourcedirv1.ListResourcesRequest{})

	want := []string{"cam.front", "cam.front.wide", "cam.rear", "base.main"}
	got := roles(out)
	if len(got) != len(want) {
		t.Fatalf("roles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected resource directory result; roles = %v, want %v type,role", got, want)
		}
	}
}

func TestListResources_OrderIsStableAcrossCalls(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	first := roles(list(t, m, &resourcedirv1.ListResourcesRequest{}))
	for i := 0; i < 20; i++ {
		next := roles(list(t, m, &resourcedirv1.ListResourcesRequest{}))
		for j := range first {
			if first[j] != next[j] {
				t.Fatalf("unexpected resource directory result; value = %d: %v vs %v", i, first, next)
			}
		}
	}
}

func TestListResources_FiltersByLabels(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	out := list(t, m, &resourcedirv1.ListResourcesRequest{
		ResourceType: camType,
		Labels:       map[string]string{"nervus.camera.facing": "front"},
	})
	got := roles(out)
	if len(got) != 2 || got[0] != "cam.front" || got[1] != "cam.front.wide" {
		t.Fatalf("roles = %v, want [cam.front cam.front.wide]", got)
	}
}

func TestListResources_LabelsAreAnded(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	out := list(t, m, &resourcedirv1.ListResourcesRequest{
		Labels: map[string]string{
			"nervus.camera.facing": "front",
			"nervus.camera.class":  "4k",
		},
	})
	if got := roles(out); len(got) != 1 || got[0] != "cam.front.wide" {
		t.Fatalf("roles = %v, want [cam.front.wide]", got)
	}
}

//

func TestListResources_NoMatchIsEmptySuccess(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	out := list(t, m, &resourcedirv1.ListResourcesRequest{
		ResourceType: "nervus.resource.lidar",
	})
	if len(out.GetResources()) != 0 {
		t.Fatalf("resources = %v, want empty", out.GetResources())
	}
}

func TestListResources_CarriesAccessMode(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	out := list(t, m, &resourcedirv1.ListResourcesRequest{})

	byRole := make(map[string]*resourcedirv1.ResourceEntry)
	for _, entry := range out.GetResources() {
		byRole[entry.GetStableRole()] = entry
	}
	if got := byRole["cam.front"].GetAccessMode(); got != ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_SHARED_OBSERVE {
		t.Errorf("cam.front access_mode = %v, want SHARED_OBSERVE", got)
	}
	if got := byRole["base.main"].GetAccessMode(); got != ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL {
		t.Errorf("base.main access_mode = %v, want EXCLUSIVE_CONTROL", got)
	}
	if got := byRole["cam.front"].GetRiskClass(); got != ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE {
		t.Errorf("cam.front risk_class = %v, want PRIVACY_SENSITIVE", got)
	}
	if got := byRole["cam.front"].GetLabels()["nervus.camera.facing"]; got != "front" {
		t.Errorf("unexpected resource directory result; cam.front facing: %q", got)
	}
}

func TestListResources_MalformedRequestIsRejected(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	result := m.BuiltinHandler()(endpoint.BuiltinCall{
		MethodID: MethodListResources,

		Payload: []byte{0x0a, 0x7f, 0x01},
	})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Fatalf("code = %v, want INVALID_ARGUMENT", result.Code)
	}
	if len(result.Payload) != 0 {
		t.Fatal("unexpected resource directory result")
	}
}

//

func TestListResources_UnknownMethodIsNotFound(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	result := m.BuiltinHandler()(endpoint.BuiltinCall{MethodID: 9999})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v, want NOT_FOUND", result.Code)
	}
}

//

func TestListResources_NilRegistryIsUnavailable(t *testing.T) {
	m := New(nil, nil)
	result := m.BuiltinHandler()(endpoint.BuiltinCall{MethodID: MethodListResources})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("code = %v, want UNAVAILABLE", result.Code)
	}
}

func TestMethodIDComesFromGeneratedEnum(t *testing.T) {
	want := uint32(resourcedirv1.ResourceDirectoryMethod_RESOURCE_DIRECTORY_METHOD_LIST_RESOURCES)
	if MethodListResources != want {
		t.Fatalf("MethodListResources = %d, want %d", MethodListResources, want)
	}
}
