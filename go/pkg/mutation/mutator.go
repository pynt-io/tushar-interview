package mutation

import (
	"interview/pkg/dto"
	"interview/pkg/rule"
	"interview/pkg/valueprovider"
)

// Mutator transforms an original request into one or more attack variants. It is
// the "what" axis of a mutation and delegates value location to an Accessor, so
// a new mutation type is a new implementation registered below — the engine's
// control flow never changes (Open/Closed).
type Mutator interface {
	Mutate(orig dto.Request, acc Accessor, field string, m rule.Mutation, vp valueprovider.ValueProvider) ([]dto.Request, error)
}

var mutatorRegistry = map[string]Mutator{
	"parameter_swap": ParameterSwap{},
	"header_inject":  HeaderInject{},
}

// MutatorFor returns the mutator registered for a mutation type, or nil.
func MutatorFor(mutationType string) Mutator {
	return mutatorRegistry[mutationType]
}
