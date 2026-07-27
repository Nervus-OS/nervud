package catalog

import (
	"errors"
	"sync/atomic"
)

// Candidate is a fully validated catalog snapshot tied to the exact base
// Snapshot from which its definition generations were derived.
type Candidate struct {
	base     *Snapshot
	snapshot *Snapshot
}

// Snapshot returns the immutable candidate view. It is safe to use for
// pre-publication permission/grant reconciliation.
func (c *Candidate) Snapshot() *Snapshot {
	if c == nil {
		return nil
	}
	return c.snapshot
}

type Registry struct {
	current atomic.Pointer[Snapshot]

	builder   *Builder
	bootstrap []Source
}

// NewRegistry validates and publishes the initial bootstrap snapshot. Every
// later Prepare automatically includes the same bootstrap sources, so package
// removal cannot accidentally remove kernel-owned definitions.
func NewRegistry(bootstrap []Source) (*Registry, error) {
	builder := NewBuilder(DefaultPolicy())
	frozenBootstrap := make([]Source, len(bootstrap))
	for i, source := range bootstrap {
		frozenBootstrap[i] = cloneSource(source)
	}
	initial, err := builder.Build(nil, frozenBootstrap)
	if err != nil {
		return nil, err
	}
	registry := &Registry{
		builder:   builder,
		bootstrap: frozenBootstrap,
	}
	registry.current.Store(initial)
	return registry, nil
}

func NewDefaultRegistry() (*Registry, error) {
	sources, err := BootstrapSources()
	if err != nil {
		return nil, err
	}
	return NewRegistry(sources)
}

func (r *Registry) Current() *Snapshot {
	if r == nil {
		return nil
	}
	return r.current.Load()
}

// Prepare builds a complete candidate from bootstrap plus the caller's complete
// set of currently installed provider sources. It performs no publication.
func (r *Registry) Prepare(sources []Source) (*Candidate, error) {
	if r == nil || r.builder == nil {
		return nil, errors.New("catalog: nil or uninitialized registry")
	}
	base := r.current.Load()
	all := make([]Source, 0, len(r.bootstrap)+len(sources))
	for _, source := range r.bootstrap {
		all = append(all, cloneSource(source))
	}
	for _, source := range sources {
		all = append(all, cloneSource(source))
	}
	next, err := r.builder.Build(base, all)
	if err != nil {
		return nil, err
	}
	return &Candidate{base: base, snapshot: next}, nil
}

// Publish atomically swaps a prepared candidate only if no other candidate has
// changed the base in the meantime.
func (r *Registry) Publish(candidate *Candidate) bool {
	if r == nil || candidate == nil || candidate.snapshot == nil {
		return false
	}
	return r.current.CompareAndSwap(candidate.base, candidate.snapshot)
}
