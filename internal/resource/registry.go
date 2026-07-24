// 本文件定义 Resource 的权威定义表（Registry）：一份构造后只读的编译期常量
// 表，回答"当前机器人 Profile 里有哪些 Resource、它们的规范 resource_type/
// role/resource_handle/access_mode 是什么"
package resource

import "fmt"

// Entry 是一条 Resource 的 v1 权威定义
type Entry struct {
	Handle string // 运行期不透明句柄，v1 恒 "base.main"
	Type   string // 规范类型，如 "nervus.resource.motion.base"
	Role   string // 稳定角色，如 "main"

	// AccessMode 是 定义的访问模式（如 "exclusive_control"）。
	// v1 只作为元数据存储，不在本包执行 - 执行/裁决仍由 internal/control 的
	// ControlLease 负责，这里只是让未来的诊断/RobotCatalog 投影有据可查
	AccessMode string
}

// entryKey 是 entries 索引的组合键
func entryKey(resourceType, role string) string {
	return resourceType + "\x00" + role
}

// Registry 是 resource 的权威状态：当前机器人 Profile 里的全部 Resource 定义
//
// 与 pkgregistry.Registry/identity.Registry/permission.Registry 的写时复制 +
// 原子指针范式不同：v1 的内容在构造后永不改变（不从 manifest 派生、没有
// 装包/卸载会触发的写入），因此不需要 atomic.Pointer 或锁 - 就是一个构造后
// 只读的 map。等 v2 需要从已验证的 Provider Descriptor 动态派生 Registry
// 内容时，再按需要引入写时复制
type Registry struct {
	entries  map[string]Entry // key: entryKey(Type, Role)
	byHandle map[string]Entry // key: Handle，供 Valid 使用
}

// NewRegistry 校验并构造一份 Registry
//
// 校验失败即整体拒绝：一份自相矛盾的定义表（重复 (Type, Role)、重复 Handle）
// 不该被静默接受后在运行期才暴露成裁决错误 - 照抄 permission.NewCatalog/
// endpoint.NewInterfaceCatalog 的自洽性校验
func NewRegistry(list []Entry) (*Registry, error) {
	entries := make(map[string]Entry, len(list))
	byHandle := make(map[string]Entry, len(list))
	for _, e := range list {
		if e.Handle == "" {
			return nil, fmt.Errorf("resource: entry has empty handle")
		}
		if e.Type == "" {
			return nil, fmt.Errorf("resource: entry %q has empty type", e.Handle)
		}
		if e.Role == "" {
			return nil, fmt.Errorf("resource: entry %q has empty role", e.Handle)
		}

		key := entryKey(e.Type, e.Role)
		if _, dup := entries[key]; dup {
			return nil, fmt.Errorf("resource: duplicate entry for type=%q role=%q", e.Type, e.Role)
		}
		if _, dup := byHandle[e.Handle]; dup {
			return nil, fmt.Errorf("resource: duplicate handle %q", e.Handle)
		}

		entries[key] = e
		byHandle[e.Handle] = e
	}
	return &Registry{entries: entries, byHandle: byHandle}, nil
}

// DefaultRegistry 返回编译期硬编码的 v1 Resource 定义表：唯一执行器 base.main
//
// 不从任何 manifest 派生 - 与 permission.DefaultCatalog/
// endpoint.DefaultInterfaceCatalog 同一个"不要在没有产品侧输入之前堆更多看起来
// 完备的条目"的自洽性原则
func DefaultRegistry() *Registry {
	reg, err := NewRegistry([]Entry{
		{
			Handle:     "base.main",
			Type:       "nervus.resource.motion.base",
			Role:       "main",
			AccessMode: "exclusive_control",
		},
	})
	if err != nil {
		// 硬编码表必须自洽；如果连这里都校验不过，说明代码本身有 bug，
		// 而不是运行期可以恢复的状况
		panic(fmt.Sprintf("resource: DefaultRegistry is invalid: %v", err))
	}
	return reg
}

// Resolve 把 (resource_type, role) 解析成运行期 resource_handle
//
// 对未初始化的 Registry（零值 &Registry{} 或 typed-nil）fail-safe 返回未命中，
// 而不是 panic - 与 permission.Registry.Allowed 等既有 Registry 的处理方式一致
// 。只做精确匹配：type 对但 role 错、role 对但 type 错、两者
// 都错，均返回未命中，不做任何模糊/前缀匹配。"空 selector 等于哪个默认值"是
// ResolveEndpoint 这个 wire 消息自身的协议层规则，属于 endpoint 侧语义，不
// 下沉到这里 - Resolve 自身不特殊处理空字符串
func (r *Registry) Resolve(resourceType, role string) (handle string, ok bool) {
	if r == nil {
		return "", false
	}
	e, ok := r.entries[entryKey(resourceType, role)]
	if !ok {
		return "", false
	}
	return e.Handle, true
}

// Valid 报告 handle 是否是 Registry 里的一个已知句柄
//
// 对未初始化的 Registry 同样 fail-safe 返回 false。NewRegistry 拒绝空 Handle
// 输入，因此空字符串天然不会出现在 byHandle 里，不需要额外特判
func (r *Registry) Valid(handle string) bool {
	if r == nil {
		return false
	}
	_, ok := r.byHandle[handle]
	return ok
}
