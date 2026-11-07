package virtual

import (
	"context"
	"fmt"
	"log/slog"
	"nervud/internal/registry"
)

type Module struct {
	service *Service
}

func (m *Module) Name() string {
	return "virtual"
}

func (m *Module) Start(ctx context.Context) error {
	slog.Info("virtual service module starting")

	// The registry must be ready before the virtual service handles requests
	// 虚拟服务处理请求前，注册表必须已经就绪
	if registry.Current() == nil {
		return fmt.Errorf("registry not initialized, ensure registry module starts before virtual")
	}

	m.service = NewService()

	globalModule = m

	slog.Info("virtual service module started")
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	slog.Info("virtual service module stopping")
	return nil
}

func (m *Module) GetService() *Service {
	return m.service
}

// Global instance
var globalModule *Module

func GetGlobalService() *Service {
	if globalModule == nil {
		return nil
	}
	return globalModule.service
}
