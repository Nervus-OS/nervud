// Package kernel 管理内核模块的有序启动与反序关闭
// 它只依赖 Module 接口，不 import 任何具体模块，以保证依赖单向
// Kernel 只认接口，装配细节留给 main，便于对生命周期做单测
package kernel

import (
	"context"
	"fmt"
	"log/slog"
)

// Module 是所有内核模块的统一生命周期契约
// Start 应快速返回：长期运行的循环自行开 goroutine，并在 ctx 取消或 Stop 时退出
type Module interface {
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type Kernel struct {
	log     *slog.Logger
	modules []Module
}

func New(log *slog.Logger) *Kernel {
	return &Kernel{log: log}
}

// Register 按调用顺序登记模块；启动顺序 = 注册顺序，关闭顺序 = 反序
// 只在 Run 之前调用（装配阶段），运行期不再增删
func (k *Kernel) Register(m Module) {
	k.modules = append(k.modules, m)
}

// Run 依次启动全部模块；任一启动失败则反序关闭已启动的模块并返回错误
// *请注意 启动失败后，不会 stop 启动失败的模块
// 全部启动成功后阻塞至 ctx 取消，再反序关闭
func (k *Kernel) Run(ctx context.Context) error {
	started := make([]Module, 0, len(k.modules))
	for _, m := range k.modules {
		k.log.Info("starting module", "module", m.Name())
		if err := m.Start(ctx); err != nil {
			k.log.Error("module failed to start; rolling back", "module", m.Name(), "err", err)
			k.stopAll(started)
			return fmt.Errorf("start %s: %w", m.Name(), err)
		}
		started = append(started, m)
	}
	k.log.Info("kernel ready", "modules", len(started))

	<-ctx.Done()
	k.log.Info("shutdown signal received; shutting down")
	k.stopAll(started)
	return nil
}

// stopAll 反序关闭所有模块 单个模块关闭出错只记录
// 用独立于 ctx 的关闭 context，避免因触发关闭的信号已使根 ctx 取消而无法收尾
func (k *Kernel) stopAll(started []Module) {
	ctx := context.Background() // TODO(rewrite): 加关闭超时（context.WithTimeout）
	for i := len(started) - 1; i >= 0; i-- {
		m := started[i]
		k.log.Info("stopping module", "module", m.Name())
		if err := m.Stop(ctx); err != nil {
			k.log.Error("module failed to stop", "module", m.Name(), "err", err)
		}
	}
}
