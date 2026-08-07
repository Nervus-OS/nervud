package catalog

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

// cameraSnapshot 造一份带三个摄像头的快照：两个前视（不同分辨率档）、一个后视。
// 这正是「按语义选设备」要解决的场景——App 想要前视，但板上有两个。
func cameraSnapshot() *Snapshot {
	const camType = "nervus.resource.camera"
	s := &Snapshot{
		revision:  1,
		resources: make(map[resourceKey]ResourceDefinition),
	}
	add := func(role string, labels map[string]string) {
		s.resources[resourceKey{resourceType: camType, stableRole: role}] = ResourceDefinition{
			Handle:       role,
			ResourceType: camType,
			StableRole:   role,
			AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_SHARED_OBSERVE,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
			Labels:       labels,
		}
	}
	add("cam.front", map[string]string{"nervus.camera.facing": "front", "nervus.camera.class": "hd"})
	add("cam.front.wide", map[string]string{"nervus.camera.facing": "front", "nervus.camera.class": "4k"})
	add("cam.rear", map[string]string{"nervus.camera.facing": "rear", "nervus.camera.class": "hd"})
	return s
}

// 按标签选设备：App 说「前视 + 4k」，不需要知道这块板上它叫 cam.front.wide。
func TestSelectResources_ByLabels(t *testing.T) {
	matched, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type: "nervus.resource.camera",
		Labels: map[string]string{
			"nervus.camera.facing": "front",
			"nervus.camera.class":  "4k",
		},
	})
	if !ok {
		t.Fatalf("唯一命中却失败: %+v", matched)
	}
	if len(matched) != 1 || matched[0].StableRole != "cam.front.wide" {
		t.Fatalf("matched = %+v, want cam.front.wide", matched)
	}
}

// 【默认 fail closed 为 REQUIRE_UNIQUE】。「我要前视」命中两个时必须报错，
// 而不是随便给一个——候选里混着不同分辨率档，随便给的后果由 App 承担。
func TestSelectResources_MultipleMatchesFailClosedByDefault(t *testing.T) {
	matched, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Labels: map[string]string{"nervus.camera.facing": "front"},
	})
	if ok {
		t.Fatalf("命中两个却成功了: %+v", matched)
	}
	if len(matched) != 2 {
		t.Fatalf("候选数 = %d, want 2（失败时仍应回候选供诊断）", len(matched))
	}
}

// 要系统替你挑，必须显式说 SYSTEM_PREFERRED。
func TestSelectResources_SystemPreferredPicksDeterministically(t *testing.T) {
	sel := &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Labels: map[string]string{"nervus.camera.facing": "front"},
		Policy: ipcv1.ResourceSelectionPolicy_RESOURCE_SELECTION_POLICY_SYSTEM_PREFERRED,
	}

	// 跑多次：Go 的 map 迭代顺序是随机化的，如果实现依赖遍历顺序，
	// 这里迟早会挑到另一个——而那种不确定性在现场极难复现
	for i := 0; i < 32; i++ {
		matched, ok := SelectResources(cameraSnapshot(), sel)
		if !ok || len(matched) != 1 {
			t.Fatalf("SYSTEM_PREFERRED 未命中单个: %+v, %v", matched, ok)
		}
		if matched[0].StableRole != "cam.front" {
			t.Fatalf("第 %d 次选到 %q，选择不确定", i, matched[0].StableRole)
		}
	}
}

func TestSelectResources_NoMatch(t *testing.T) {
	if matched, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Labels: map[string]string{"nervus.camera.facing": "up"},
	}); ok || len(matched) != 0 {
		t.Fatalf("不该命中: %+v, %v", matched, ok)
	}
}

// role 与 labels 叠加过滤：给了 role 仍要满足 labels。
func TestSelectResources_RoleAndLabelsCombine(t *testing.T) {
	if _, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Role:   "cam.rear",
		Labels: map[string]string{"nervus.camera.facing": "front"},
	}); ok {
		t.Fatal("role 与 label 矛盾时不该命中")
	}
}

// 未知策略必须 fail closed：协议新增了本 build 不认识的值时按最严处理，不猜。
func TestSelectResources_UnknownPolicyFailsClosed(t *testing.T) {
	if _, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Role:   "cam.rear",
		Policy: ipcv1.ResourceSelectionPolicy(99),
	}); ok {
		t.Fatal("未知策略被放行")
	}
}

// 只带 labels 的 selector 是明确的语义查询，不能被当成「空」而回落到默认资源。
func TestSelectorIsEmpty(t *testing.T) {
	cases := []struct {
		name  string
		sel   *ipcv1.ResourceSelector
		empty bool
	}{
		{"nil", nil, true},
		{"全空", &ipcv1.ResourceSelector{}, true},
		{"只有 type", &ipcv1.ResourceSelector{Type: "t"}, false},
		{"只有 role", &ipcv1.ResourceSelector{Role: "r"}, false},
		{"只有 labels", &ipcv1.ResourceSelector{Labels: map[string]string{"k": "v"}}, false},
		{"只有 policy", &ipcv1.ResourceSelector{
			Policy: ipcv1.ResourceSelectionPolicy_RESOURCE_SELECTION_POLICY_SYSTEM_PREFERRED,
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SelectorIsEmpty(tc.sel); got != tc.empty {
				t.Fatalf("SelectorIsEmpty = %v, want %v", got, tc.empty)
			}
		})
	}
}

// 返回的定义必须是深拷贝：Snapshot 不可变，交出内部 map 会让消费者能就地
// 改写一份已发布的 Catalog。
func TestSelectResources_ReturnsDeepCopy(t *testing.T) {
	snapshot := cameraSnapshot()
	matched, ok := SelectResources(snapshot, &ipcv1.ResourceSelector{
		Type: "nervus.resource.camera", Role: "cam.rear",
	})
	if !ok {
		t.Fatal("未命中")
	}
	matched[0].Labels["nervus.camera.facing"] = "tampered"

	again, _ := SelectResources(snapshot, &ipcv1.ResourceSelector{
		Type: "nervus.resource.camera", Role: "cam.rear",
	})
	if again[0].Labels["nervus.camera.facing"] != "rear" {
		t.Fatal("SelectResources 交出了内部 map，快照被就地改写了")
	}
}
