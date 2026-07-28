package mutation

import (
	"fmt"

	"interview/pkg/dto"
	"interview/pkg/rule"
	"interview/pkg/valueprovider"
)

// ParameterSwap replaces a target value with modified variants. The "increment"
// strategy produces two variants (value+1 and value-1); the original request is
// never modified.
type ParameterSwap struct{}

func (ParameterSwap) Mutate(orig dto.Request, acc Accessor, field string, m rule.Mutation, vp valueprovider.ValueProvider) ([]dto.Request, error) {
	domain, _ := ParseTarget(m.Target)

	cur, ok := acc.Get(orig, field)
	if !ok {
		cur = vp.BaseValue(domain, field)
	}

	n, err := toInt(cur)
	if err != nil {
		return nil, fmt.Errorf("parameter_swap on %q: %w", m.Target, err)
	}

	switch m.Strategy {
	case "increment":
		var out []dto.Request
		for _, delta := range []int{+1, -1} {
			v := orig.Clone()
			acc.Set(&v, field, n+delta)
			out = append(out, v)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("parameter_swap: unsupported strategy %q", m.Strategy)
	}
}
