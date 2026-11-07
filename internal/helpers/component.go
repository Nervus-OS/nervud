package helpers

import (
	"errors"
	"nervud/internal/registry"
)

func ExecuteComponent(target registry.Component, arg string) error {
	if target.Type == registry.ComponentTypeApp {
		return errors.New("app execution not implemented")
	} else if target.Type == registry.ComponentTypeService {
		/* TODO */
	} else {
		return errors.New("invalid component type")
	}
	return nil
}
