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

// deviceRegistry 造一个装了三个摄像头和一个底盘的 Catalog。
//
// 走真的 catalog.Registry + Source 而不是手搓 Snapshot：本包读的是 Catalog 的
// 权威投影，用手搓快照测等于绕开了「Catalog 到底会不会这样投影」这个问题。
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

// 空请求列出全部——【枚举天生是多值的】，这正是目录存在的理由。
//
// 若这里回落到 ResourceSelector 的 REQUIRE_UNIQUE 语义，「有哪些设备」会因为
// 命中多个而失败，目录就白做了。
func TestListResources_EmptyRequestListsAll(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	out := list(t, m, &resourcedirv1.ListResourcesRequest{})

	// 排序主键是 resource_type：nervus.resource.camera 整组排在
	// nervus.resource.motion.base 之前，组内再按 stable_role。
	want := []string{"cam.front", "cam.front.wide", "cam.rear", "base.main"}
	got := roles(out)
	if len(got) != len(want) {
		t.Fatalf("roles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("roles = %v, want %v（按 type,role 字典序）", got, want)
		}
	}
}

// 顺序必须确定。Go 的 map 迭代顺序是随机的，直接返回遍历结果会让 UI 里的
// 设备列表每次刷新都在跳——而这种问题几乎不会有人报成 bug。
func TestListResources_OrderIsStableAcrossCalls(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	first := roles(list(t, m, &resourcedirv1.ListResourcesRequest{}))
	for i := 0; i < 20; i++ {
		next := roles(list(t, m, &resourcedirv1.ListResourcesRequest{}))
		for j := range first {
			if first[j] != next[j] {
				t.Fatalf("第 %d 次顺序变了: %v vs %v", i, first, next)
			}
		}
	}
}

// 按标签查：App 说「前视」，不需要知道这块板上它叫什么。
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

// 多个标签是 AND，不是 OR。OR 会让「前视且 4k」返回所有前视加所有 4k。
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

// 无命中回空列表 + OK，不是 NOT_FOUND。
//
// 「这台机器上没有深度相机」是一个【成功的查询结果】，不是一次失败。回
// NOT_FOUND 会逼调用方把「没有」和「查不了」当成同一件事处理。
func TestListResources_NoMatchIsEmptySuccess(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	out := list(t, m, &resourcedirv1.ListResourcesRequest{
		ResourceType: "nervus.resource.lidar",
	})
	if len(out.GetResources()) != 0 {
		t.Fatalf("resources = %v, want empty", out.GetResources())
	}
}

// 条目必须带 access_mode：它决定 App 要不要去申请租约。
// 摄像头是 SHARED_OBSERVE（多方同看），底盘是 EXCLUSIVE_CONTROL（必须先拿租约）。
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
		t.Errorf("cam.front facing 标签丢了: %q", got)
	}
}

// 解不开的请求回 INVALID_ARGUMENT，【不能】当成空请求列出全部——
// 那会把一次编码错误变成一次全量泄漏。
func TestListResources_MalformedRequestIsRejected(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	result := m.BuiltinHandler()(endpoint.BuiltinCall{
		MethodID: MethodListResources,
		// 字段号 1 声明为 length-delimited，但长度前缀指向缓冲区之外
		Payload: []byte{0x0a, 0x7f, 0x01},
	})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Fatalf("code = %v, want INVALID_ARGUMENT", result.Code)
	}
	if len(result.Payload) != 0 {
		t.Fatal("失败响应不该带载荷")
	}
}

// 未实现的 method_id fail closed 回 NOT_FOUND。
//
// 回一个空列表会让调用方以为这台机器上什么资源都没有。
func TestListResources_UnknownMethodIsNotFound(t *testing.T) {
	m := New(deviceRegistry(t), nil)
	result := m.BuiltinHandler()(endpoint.BuiltinCall{MethodID: 9999})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v, want NOT_FOUND", result.Code)
	}
}

// 没有 Catalog 时 fail closed 回 UNAVAILABLE，而不是回空列表。
//
// 空列表意味着「我查过了，没有」；UNAVAILABLE 意味着「我查不了」。装配未完成
// 时给出前者，会让调用方据此认定设备不存在并走进降级分支。
func TestListResources_NilRegistryIsUnavailable(t *testing.T) {
	m := New(nil, nil)
	result := m.BuiltinHandler()(endpoint.BuiltinCall{MethodID: MethodListResources})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("code = %v, want UNAVAILABLE", result.Code)
	}
}

// method_id 必须来自生成代码，不能是本地抄的字面量——抄一份会悄悄过期。
func TestMethodIDComesFromGeneratedEnum(t *testing.T) {
	want := uint32(resourcedirv1.ResourceDirectoryMethod_RESOURCE_DIRECTORY_METHOD_LIST_RESOURCES)
	if MethodListResources != want {
		t.Fatalf("MethodListResources = %d, want %d", MethodListResources, want)
	}
}
