// 本文件把 permission 接入 kernel.Module 生命周期
package permission

import "context"

// Module 把 permission 接入 kernel.Module 生命周期
//
// Registry 的全量状态由 pkgregistry 在装包/卸载/启动扫描后主动推送
// （Registry.Replace），不是 Module 在 Start 里反过来拉取 - 这与
// identity.Registry 接收 pkgregistry 投影的方式一致（见
// pkgregistry/module.go 的 projectIdentity）。因此 Module 本身没有需要
// 建立的初始状态：Registry 在装配阶段由 main.go 构造好并共享给
// pkgregistry 与 permission 双方，Start/Stop 只是把 permission 正式纳入
// Kernel 的启停序列，供后续（如 Fatal 上报）扩展
//
// 注册顺序排在 pkgregistry 之后（它的 Grant 投影来自 pkgregistry 的推送）、
// ipc 之前（ipc 依赖它做 Request 分派前的权限裁决）
type Module struct {
	registry *Registry
}

// New 构造 permission 的 Module
//
// registry 由调用方在装配阶段显式 NewRegistry(cat) 构造后传入，而不是本
// 函数内部 new - pkgregistry 需要与 Module 共享同一份 *Registry 才能把
// Install/Scan 的投影推送到它，两者不能各自持有一份互不知情的副本
func New(registry *Registry) *Module {
	return &Module{registry: registry}
}

func (m *Module) Name() string { return "permission" }

// Start 没有需要执行的初始化逻辑：Registry 从构造起就是可用状态（空授权集，
// Allowed 一律拒绝），首份真实数据由 pkgregistry 自己的 Start 推送进来
func (m *Module) Start(_ context.Context) error { return nil }

// Stop 纯内存态，没有需要释放的资源
func (m *Module) Stop(_ context.Context) error { return nil }
