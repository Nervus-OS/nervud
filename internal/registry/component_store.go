package registry

import (
	"encoding/json"
	"fmt"
	"nervud/internal/config"
	"os"
	"sync"
)

type ComponentStore struct {
	mu         sync.RWMutex
	components map[string]*Component // ID -> Component
	uidIndex   map[int32]*Component  // UID -> Component
	filePath   string
}

func NewComponentStore() *ComponentStore {
	return &ComponentStore{
		components: make(map[string]*Component),
		uidIndex:   make(map[int32]*Component),
		filePath:   config.Get().ComponentRegistryPath,
	}
}

func (s *ComponentStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if the component registry file exists
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		return nil
	}

	// Load components from the JSON file
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("read registry file: %w", err)
	}

	// Parse JSON
	var components []*Component
	if err := json.Unmarshal(data, &components); err != nil {
		return fmt.Errorf("unmarshal registry: %w", err)
	}

	// Build indexes
	s.components = make(map[string]*Component)
	s.uidIndex = make(map[int32]*Component)
	for _, comp := range components {
		s.components[comp.ID] = comp
		s.uidIndex[comp.UID] = comp
	}

	return nil
}

// save writes the registry to file atomically
func (s *ComponentStore) save() error {
	// Convert map to array
	components := make([]*Component, 0, len(s.components))
	for _, comp := range s.components {
		components = append(components, comp)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(components, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal registry: %w", err)
	}

	// Write to temporary file
	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpFile, s.filePath); err != nil {
		// Clean up temp file on failure
		_ = os.Remove(tmpFile)
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// GetComponent retrieves a component by ID
func (s *ComponentStore) GetComponent(id string) *Component {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.components[id]
}

// GetComponentByUID retrieves a component by UID
func (s *ComponentStore) GetComponentByUID(uid int32) *Component {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.uidIndex[uid]
}

// ListComponents returns all components
func (s *ComponentStore) ListComponents() []*Component {
	s.mu.RLock()
	defer s.mu.RUnlock()

	components := make([]*Component, 0, len(s.components))
	for _, comp := range s.components {
		components = append(components, comp)
	}
	return components
}

// RegisterComponent registers a new component
func (s *ComponentStore) RegisterComponent(comp *Component) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if component already exists
	if _, exists := s.components[comp.ID]; exists {
		return fmt.Errorf("component already exists: %s", comp.ID)
	}

	// Check if UID is already in use
	if existing, exists := s.uidIndex[comp.UID]; exists {
		return fmt.Errorf("UID %d already in use by component: %s", comp.UID, existing.ID)
	}

	// Add to indexes
	s.components[comp.ID] = comp
	s.uidIndex[comp.UID] = comp

	// Persist to disk
	return s.save()
}

// UnregisterComponent removes a component from the registry
func (s *ComponentStore) UnregisterComponent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	comp, exists := s.components[id]
	if !exists {
		return fmt.Errorf("component not found: %s", id)
	}

	// Remove from indexes
	delete(s.components, id)
	delete(s.uidIndex, comp.UID)

	return s.save()
}

// UpdateAvailability updates a component's availability status
func (s *ComponentStore) UpdateAvailability(id string, available bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	comp, exists := s.components[id]
	if !exists {
		return fmt.Errorf("component not found: %s", id)
	}

	comp.IsAvailable = available

	return s.save()
}

// ConfirmPermission marks a permission as confirmed for a component
func (s *ComponentStore) ConfirmPermission(compID, permID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	comp, exists := s.components[compID]
	if !exists {
		return fmt.Errorf("component not found: %s", compID)
	}

	// Find and confirm the permission
	found := false
	for i := range comp.Permissions {
		if comp.Permissions[i].ID == permID {
			comp.Permissions[i].IsConfirmed = true
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("permission not found: %s", permID)
	}

	// Persist to disk
	return s.save()
}
