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

	// Get the global component store from the registry module
	store := registry.GetGlobalStore()
	if store == nil {
		return fmt.Errorf("component store not initialized, ensure registry module starts before virtual")
	}

	m.service = NewService(store)

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
