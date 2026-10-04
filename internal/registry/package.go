package registry

import (
	"context"
	"log/slog"
	"nervud/internal/kernel"
)

var globalStore *ComponentStore

type Module struct {
	store *ComponentStore
}

func (m *Module) Name() string {
	return "registry_package"
}

func (m *Module) Start(ctx context.Context) error {
	slog.Info("registry module starting")

	// Initialize component store
	m.store = NewComponentStore()

	// Load registry
	if err := m.store.Load(); err != nil {
		slog.Error("failed to load component registry", "error", err)
		kernel.ReportFatal(ctx, err)
		return err
	}

	componentCount := len(m.store.ListComponents())
	slog.Info("component registry loaded", "component_count", componentCount)

	// Set global store for other modules to access
	globalStore = m.store

	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	defer slog.Info("registry module stopping")

	if m.store != nil {
		// Save current state to disk before shutdown
		if err := m.store.save(); err != nil {
			slog.Error("failed to save component registry", "error", err)
			return err
		}
		slog.Info("component registry saved")
	}

	return nil
}

func GetGlobalStore() *ComponentStore {
	return globalStore
}
