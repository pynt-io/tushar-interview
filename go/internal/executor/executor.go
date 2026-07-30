package executor

import (
	"time"

	"interview/internal/matcher"
	_ "interview/internal/mutate"
	"interview/internal/mutation"
	"interview/internal/request"
	"interview/internal/result"
	"interview/internal/rules"
	"interview/pkg/specparser"
)

type RunOptions struct {
	SendRequests          bool
	DefaultPathParamValue string
}

func Run(loadedRules []rules.Rule, endpoints []specparser.Endpoint, opts RunOptions) []result.Result {
	if opts.DefaultPathParamValue == "" {
		opts.DefaultPathParamValue = "42"
	}

	matches := matcher.MatchAll(loadedRules, endpoints)
	results := make([]result.Result, 0, len(matches))

	for _, match := range matches {
		baseline := request.NewBaselineAttackRequest(match.Endpoint, opts.DefaultPathParamValue)

		for _, mut := range match.Rule.Mutations {
			mutator, ok := mutation.Get(mut.Type)
			if !ok {
				results = append(results, result.Result{
					RuleID:          match.Rule.ID,
					RuleName:        match.Rule.Name,
					Severity:        match.Rule.Severity,
					Endpoint:        match.Endpoint.Path,
					Method:          match.Endpoint.Method,
					MutationSummary: mut.Type,
					ResolvedPath:    baseline.ResolvedPath,
					Status:          "error",
					Error:           "unknown mutation type",
					Timestamp:       time.Now(),
				})
				continue
			}

			attackRequests, err := mutator.Apply(baseline, mut)
			if err != nil {
				results = append(results, result.Result{
					RuleID:          match.Rule.ID,
					RuleName:        match.Rule.Name,
					Severity:        match.Rule.Severity,
					Endpoint:        match.Endpoint.Path,
					Method:          match.Endpoint.Method,
					MutationSummary: mut.Type,
					ResolvedPath:    baseline.ResolvedPath,
					Status:          "error",
					Error:           err.Error(),
					Timestamp:       time.Now(),
				})
				continue
			}

			for _, attack := range attackRequests {
				res := result.Result{
					RuleID:          match.Rule.ID,
					RuleName:        match.Rule.Name,
					Severity:        match.Rule.Severity,
					Endpoint:        match.Endpoint.Path,
					Method:          match.Endpoint.Method,
					MutationSummary: attack.MutationApplied,
					ResolvedPath:    attack.ResolvedPath,
					Timestamp:       time.Now(),
				}

				if opts.SendRequests {
					// SendRequests is not implemented in this version.
					res.Status = "generated_not_sent"
				} else {
					res.Status = "generated_not_sent"
				}

				results = append(results, res)
			}
		}
	}

	return results
}
