package mutation

import (
	"interview/pkg/dto"
	"interview/pkg/rule"
	"interview/pkg/valueprovider"
)

// HeaderInject sets or replaces an HTTP header with the rule's value (an empty
// value is valid and meaningful — e.g. blanking Authorization). It produces a
// single variant.
type HeaderInject struct{}

func (HeaderInject) Mutate(orig dto.Request, acc Accessor, field string, m rule.Mutation, vp valueprovider.ValueProvider) ([]dto.Request, error) {
	v := orig.Clone()
	acc.Set(&v, field, m.Value)
	return []dto.Request{v}, nil
}
