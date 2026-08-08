package catalog

import (
	"sort"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

// SelectResources 按 ResourceSelector 挑资源.
//
// # 匹配规则
//
//	type 非空时精确匹配
//	role 非空时精确匹配
//	labels 全部键值都要命中 (AND); 空 map 不过滤
//
// # 多候选怎么办
//
// 由 policy 决定, 未指定 fail closed 为 REQUIRE_UNIQUE.
//
// 对机器人来说"我要一个摄像头, 系统随便给了一个"比一个明确的错误危险得多 -
// 尤其当候选里混着前视和后视, 或者左臂和右臂. 要系统替你挑, 必须显式说出来.
//
// SYSTEM_PREFERRED 取 stable_role 字典序最小者. 挑一个确定的而不是遍历
// map 拿到的第一个: Go 的 map 迭代顺序是随机化的, 那样同一份 Catalog 在两次
// 启动上会选到不同设备, 而这种不确定性在现场极难复现.
func SelectResources(
	snapshot *Snapshot, sel *ipcv1.ResourceSelector,
) ([]ResourceDefinition, bool) {
	if snapshot == nil {
		return nil, false
	}

	if sel == nil {
		// 空 selector 在 v2 里不再隐式指向底盘. 没有目标就是没有目标.
		return nil, false
	}
	matched := FilterResources(snapshot, sel.GetType(), sel.GetRole(), sel.GetLabels())
	if len(matched) == 0 {
		return nil, false
	}

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
		// 未知策略 fail closed. 协议新增了一个本 build 不认识的值时,
		// 按最严处理而不是猜
		return matched, false
	}
}

// FilterResources 列出全部匹配项, 不做"多候选挑哪一个"的裁决.
//
// 与 SelectResources 分开是因为两者回答的是不同的问题. SelectResources 回答
// "把我接到哪一个上", 多候选是个必须被解决的歧义; FilterResources 回答
// "有哪些", 多候选正是答案本身. 让枚举也走 policy, 就得给它硬塞一个
// SYSTEM_PREFERRED - 那会让"列出全部摄像头"返回一个.
//
// 顺序按 (ResourceType, StableRole) 字典序. Go 的 map 迭代顺序是随机化的,
// 直接返回遍历结果会让同一份 Catalog 在两次调用上给出不同顺序, UI 里的表现
// 是设备列表每次刷新都在跳 - 而这种问题几乎不会有人报成 bug.
func FilterResources(
	snapshot *Snapshot,
	resourceType string,
	stableRole string,
	labels map[string]string,
) []ResourceDefinition {
	if snapshot == nil {
		return nil
	}
	var matched []ResourceDefinition
	for _, def := range snapshot.resources {
		if !matchesFields(def, resourceType, stableRole, labels) {
			continue
		}
		matched = append(matched, cloneResourceDefinition(def))
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].ResourceType != matched[j].ResourceType {
			return matched[i].ResourceType < matched[j].ResourceType
		}
		return matched[i].StableRole < matched[j].StableRole
	})
	return matched
}

// matchesFields 是匹配规则的唯一实现, SelectResources 与 FilterResources 共用.
//
// 空字段 = 不过滤; labels 全部键值都要命中 (AND).
func matchesFields(
	def ResourceDefinition,
	resourceType string,
	stableRole string,
	labels map[string]string,
) bool {
	if resourceType != "" && def.ResourceType != resourceType {
		return false
	}
	if stableRole != "" && def.StableRole != stableRole {
		return false
	}
	for key, want := range labels {
		got, ok := def.Labels[key]
		if !ok || got != want {
			return false
		}
	}
	return true
}

// SelectorIsEmpty 报告 selector 是否什么都没指定 - 调用方据此回落到接口的
// 默认资源. labels 与 policy 单独出现也算"指定了": 一个只带 labels 的
// selector 是明确的语义查询, 不该被当成空.
func SelectorIsEmpty(sel *ipcv1.ResourceSelector) bool {
	return sel == nil ||
		(sel.GetType() == "" &&
			sel.GetRole() == "" &&
			len(sel.GetLabels()) == 0 &&
			sel.GetPolicy() == ipcv1.ResourceSelectionPolicy_RESOURCE_SELECTION_POLICY_UNSPECIFIED)
}
