package catalog

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

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

func TestSelectResources_ByLabels(t *testing.T) {
	matched, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type: "nervus.resource.camera",
		Labels: map[string]string{
			"nervus.camera.facing": "front",
			"nervus.camera.class":  "4k",
		},
	})
	if !ok {
		t.Fatalf("unexpected catalog result; value = %+v", matched)
	}
	if len(matched) != 1 || matched[0].StableRole != "cam.front.wide" {
		t.Fatalf("matched = %+v, want cam.front.wide", matched)
	}
}

func TestSelectResources_MultipleMatchesFailClosedByDefault(t *testing.T) {
	matched, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Labels: map[string]string{"nervus.camera.facing": "front"},
	})
	if ok {
		t.Fatalf("unexpected catalog result; value = %+v", matched)
	}
	if len(matched) != 2 {
		t.Fatalf("unexpected catalog result; value = %d, want 2", len(matched))
	}
}

func TestSelectResources_SystemPreferredPicksDeterministically(t *testing.T) {
	sel := &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Labels: map[string]string{"nervus.camera.facing": "front"},
		Policy: ipcv1.ResourceSelectionPolicy_RESOURCE_SELECTION_POLICY_SYSTEM_PREFERRED,
	}

	for i := 0; i < 32; i++ {
		matched, ok := SelectResources(cameraSnapshot(), sel)
		if !ok || len(matched) != 1 {
			t.Fatalf("unexpected catalog result; SYSTEM_PREFERRED: %+v, %v", matched, ok)
		}
		if matched[0].StableRole != "cam.front" {
			t.Fatalf("unexpected catalog result; value = %d %q", i, matched[0].StableRole)
		}
	}
}

func TestSelectResources_NoMatch(t *testing.T) {
	if matched, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Labels: map[string]string{"nervus.camera.facing": "up"},
	}); ok || len(matched) != 0 {
		t.Fatalf("unexpected catalog result; value = %+v, %v", matched, ok)
	}
}

func TestSelectResources_RoleAndLabelsCombine(t *testing.T) {
	if _, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Role:   "cam.rear",
		Labels: map[string]string{"nervus.camera.facing": "front"},
	}); ok {
		t.Fatal("unexpected catalog result; role label")
	}
}

func TestSelectResources_UnknownPolicyFailsClosed(t *testing.T) {
	if _, ok := SelectResources(cameraSnapshot(), &ipcv1.ResourceSelector{
		Type:   "nervus.resource.camera",
		Role:   "cam.rear",
		Policy: ipcv1.ResourceSelectionPolicy(99),
	}); ok {
		t.Fatal("unexpected catalog result")
	}
}

func TestSelectorIsEmpty(t *testing.T) {
	cases := []struct {
		name  string
		sel   *ipcv1.ResourceSelector
		empty bool
	}{
		{"nil", nil, true},
		{"catalog test value 014111", &ipcv1.ResourceSelector{}, true},
		{"catalog test value 0fc403; type", &ipcv1.ResourceSelector{Type: "t"}, false},
		{"catalog test value ec929d; role", &ipcv1.ResourceSelector{Role: "r"}, false},
		{"catalog test value 1562c2; labels", &ipcv1.ResourceSelector{Labels: map[string]string{"k": "v"}}, false},
		{"catalog test value 9b3a81; policy", &ipcv1.ResourceSelector{
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

func TestSelectResources_ReturnsDeepCopy(t *testing.T) {
	snapshot := cameraSnapshot()
	matched, ok := SelectResources(snapshot, &ipcv1.ResourceSelector{
		Type: "nervus.resource.camera", Role: "cam.rear",
	})
	if !ok {
		t.Fatal("unexpected catalog result")
	}
	matched[0].Labels["nervus.camera.facing"] = "tampered"

	again, _ := SelectResources(snapshot, &ipcv1.ResourceSelector{
		Type: "nervus.resource.camera", Role: "cam.rear",
	})
	if again[0].Labels["nervus.camera.facing"] != "rear" {
		t.Fatal("unexpected catalog result; SelectResources map")
	}
}
