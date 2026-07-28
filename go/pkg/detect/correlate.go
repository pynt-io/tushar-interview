package detect

import (
	"interview/pkg/dto"
	"interview/pkg/rule"
)

// Correlate joins each attack request with its response (index-aligned) and the
// rule that produced it (via the provenance carried on the AttackRequest),
// producing a structured result per attack variant.
func Correlate(attacks []dto.AttackRequest, responses []dto.Response, rules []rule.Rule) []dto.Result {
	byID := make(map[string]rule.Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}

	results := make([]dto.Result, 0, len(attacks))
	for i, a := range attacks {
		var resp dto.Response
		if i < len(responses) {
			resp = responses[i]
		}
		r := byID[a.RuleID]
		vuln, ev := Detect(r.Detection, resp)
		results = append(results, dto.Result{
			RuleID:     a.RuleID,
			Endpoint:   a.Endpoint,
			Mutation:   a.Mutation,
			Sent:       true,
			Vulnerable: vuln,
			Evidence:   ev,
		})
	}
	return results
}
