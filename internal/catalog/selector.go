package catalog

import (
	"sort"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

// SelectResources 按 ResourceSelector 挑资源。
//
// # 匹配规则
//
//	type   非空时精确匹配
//	role   非空时精确匹配
//	labels 全部键值都要命中（AND）；空 map 不过滤
//
// # 多候选怎么办
//
// 由 policy 决定，【未指定 fail closed 为 REQUIRE_UNIQUE】。
//
// 对机器人来说「我要一个摄像头，系统随便给了一个」比一个明确的错误危险得多——
// 尤其当候选里混着前视和后视，或者左臂和右臂。要系统替你挑，必须显式说出来。
//
// SYSTEM_PREFERRED 取 stable_role 字典序最小者。挑一个【确定的】而不是遍历
// map 拿到的第一个：Go 的 map 迭代顺序是随机化的，那样同一份 Catalog 在两次
// 启动上会选到不同设备，而这种不确定性在现场极难复现。
func SelectResources(
	snapshot *Snapshot, sel *ipcv1.ResourceSelector,
) ([]ResourceDefinition, bool) {
	if snapshot == nil {
		return nil, false
	}

	var matched []ResourceDefinition
	for _, def := range snapshot.resources {
		if !matchesSelector(def, sel) {
			continue
		}
		matched = append(matched, cloneResourceDefinition(def))
	}
	if len(matched) == 0 {
		return nil, false
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].ResourceType != matched[j].ResourceType {
			return matched[i].ResourceType < matched[j].ResourceType
		}
		return matched[i].StableRole < matched[j].StableRole
	})

	switch sel.GetPolicy() {
	case ipcv1.ResourceSelectionPolicy_RESOURCE_SELECTION_POLICY_SYSTEM_PREFERRED:
		return matched[:1], true
	case ipcv1.ResourceSelectionPolicy_RESOURCE_SELECTION_POLICY_REQUIRE_UNIQUE,
		ipcv1.ResourceSelectionPolicy_RESOURCE_SELECTION_POLICY_UNSPECIFIED:
		if len(matched) != 1 {
			return matched, false
		}
		return matched, true
	default:
		// 未知策略 fail closed。协议新增了一个本 build 不认识的值时，
		// 按最严处理而不是猜
		return matched, false
	}
}

func matchesSelector(def ResourceDefinition, sel *ipcv1.ResourceSelector) bool {
	if sel == nil {
		return false
	}
	if t := sel.GetType(); t != "" && def.ResourceType != t {
		return false
	}
	if r := sel.GetRole(); r != "" && def.StableRole != r {
		return false
	}
	for key, want := range sel.GetLabels() {
		got, ok := def.Labels[key]
		if !ok || got != want {
			return false
		}
	}
	return true
}

// SelectorIsEmpty 报告 selector 是否什么都没指定——调用方据此回落到接口的
// 默认资源。labels 与 policy 单独出现也算「指定了」：一个只带 labels 的
// selector 是明确的语义查询，不该被当成空。
func SelectorIsEmpty(sel *ipcv1.ResourceSelector) bool {
	return sel == nil ||
		(sel.GetType() == "" &&
			sel.GetRole() == "" &&
			len(sel.GetLabels()) == 0 &&
			sel.GetPolicy() == ipcv1.ResourceSelectionPolicy_RESOURCE_SELECTION_POLICY_UNSPECIFIED)
}
