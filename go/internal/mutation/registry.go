package mutation

import (
	"fmt"

	"interview/internal/domain"
)

// Mutator applies a single mutation type to a request.
type Mutator interface {
	Type() string
	Apply(req domain.Request, m domain.Mutation) ([]domain.RequestVariant, error)
}

// Registry maps mutation type names to implementations.
type Registry struct {
	mutators map[string]Mutator
}

// NewRegistry returns a registry with the built-in mutators registered.
func NewRegistry(mutators ...Mutator) *Registry {
	r := &Registry{mutators: make(map[string]Mutator)}
	for _, m := range mutators {
		r.Register(m)
	}
	return r
}

// DefaultRegistry returns the standard mutator set.
func DefaultRegistry() *Registry {
	return NewRegistry(
		ParameterSwap{},
		HeaderInject{},
	)
}

// Register adds or replaces a mutator by its type name.
func (r *Registry) Register(m Mutator) {
	r.mutators[m.Type()] = m
}

// Apply runs all mutations on a base request and returns combined variants.
// Mutations are applied independently against the original request (not chained).
func (r *Registry) Apply(req domain.Request, mutations []domain.Mutation) ([]domain.RequestVariant, error) {
	var all []domain.RequestVariant
	for _, m := range mutations {
		mutator, ok := r.mutators[m.Type]
		if !ok {
			return nil, fmt.Errorf("unsupported mutation type %q", m.Type)
		}
		variants, err := mutator.Apply(req, m)
		if err != nil {
			return nil, fmt.Errorf("apply mutation %s: %w", m.Type, err)
		}
		all = append(all, variants...)
	}
	return all, nil
}
