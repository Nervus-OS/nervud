// 见 doc.go 的包说明
//
// 本文件把 resource 接入 kernel.Module 生命周期
package resource

import "context"

// Module 把 resource 接入 kernel.Module 生命周期，并把 *Registry 的
// Resolve/Valid 转发出去，使 *Module 本身即可满足 internal/endpoint 定义的
// ResourceResolver 窄接口（设计方案 §6 main.go 装配示例）
//
// v1 的 Registry 内容在构造时就完全确定（编译期常量，见 DefaultRegistry），
// 没有需要启动的后台循环，也没有需要停机时收尾的状态——Start/Stop 都是空
// 操作。做成 Module 而不是像 identity 现在这样的裸库，是为了不让"库 →
// Module 外壳"这个技术债在 resource 身上重演一次（设计方案 §2）
type Module struct {
	registry *Registry
}

// New 构造 resource 的 Module
//
// registry 由调用方在装配阶段构造后传入（通常是 DefaultRegistry()），
// 与 permission.New(registry) 的既有范式一致
func New(registry *Registry) *Module {
	return &Module{registry: registry}
}

func (m *Module) Name() string { return "resource" }

// Start 无需要执行的初始化逻辑：Registry 从构造起就是可用状态
func (m *Module) Start(_ context.Context) error { return nil }

// Stop 纯内存态，没有需要释放的资源
func (m *Module) Stop(_ context.Context) error { return nil }

// Resolve 转发给底层 *Registry，对 nil Module fail-safe 返回未命中
func (m *Module) Resolve(resourceType, role string) (handle string, ok bool) {
	if m == nil {
		return "", false
	}
	return m.registry.Resolve(resourceType, role)
}

// Valid 转发给底层 *Registry，对 nil Module fail-safe 返回 false
func (m *Module) Valid(handle string) bool {
	if m == nil {
		return false
	}
	return m.registry.Valid(handle)
}
