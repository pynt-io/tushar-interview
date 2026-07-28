package engine

import (
	"fmt"

	"interview/pkg/dto"
	"interview/pkg/matcher"
	"interview/pkg/mutation"
	"interview/pkg/rule"
	"interview/pkg/specparser"
	"interview/pkg/valueprovider"
)

// Warning is a non-fatal problem encountered while running an otherwise valid
// rule (e.g. an unknown mutation type or a value that can't be mutated).
type Warning struct {
	RuleID  string
	Message string
}

// Run executes the core pipeline: for every (rule, endpoint) pair that matches,
// it builds the original request and applies each mutation to generate tagged
// attack variants. It sends nothing — producing requests is the deliverable;
// sending them is the sender's job.
func Run(rules []rule.Rule, endpoints []specparser.Endpoint, vp valueprovider.ValueProvider) ([]dto.AttackRequest, []Warning) {
	var attacks []dto.AttackRequest
	var warnings []Warning

	for _, r := range rules {
		for _, ep := range endpoints {
			if !matcher.Match(r, ep) {
				continue
			}

			orig := mutation.FromEndpoint(ep, vp)

			for _, m := range r.Mutations {
				domain, field := mutation.ParseTarget(m.Target)

				acc := mutation.AccessorFor(domain)
				if acc == nil {
					warnings = append(warnings, Warning{r.ID, fmt.Sprintf("unknown target domain %q in %q", domain, m.Target)})
					continue
				}
				mut := mutation.MutatorFor(m.Type)
				if mut == nil {
					warnings = append(warnings, Warning{r.ID, fmt.Sprintf("unknown mutation type %q", m.Type)})
					continue
				}

				variants, err := mut.Mutate(orig, acc, field, m, vp)
				if err != nil {
					warnings = append(warnings, Warning{r.ID, err.Error()})
					continue
				}

				for _, v := range variants {
					attacks = append(attacks, dto.AttackRequest{
						RuleID:   r.ID,
						RuleName: r.Name,
						Endpoint: ep.String(),
						Mutation: describe(m),
						Request:  v,
					})
				}
			}
		}
	}

	return attacks, warnings
}

func describe(m rule.Mutation) string {
	switch m.Type {
	case "parameter_swap":
		return fmt.Sprintf("parameter_swap %s on %s", m.Strategy, m.Target)
	case "header_inject":
		return fmt.Sprintf("header_inject %s=%q", m.Target, m.Value)
	default:
		return m.Type
	}
}
