package engine

import (
	"fmt"
	"strings"

	"interview/internal/config"
	"interview/internal/detection"
	"interview/internal/domain"
	"interview/internal/loader"
	"interview/internal/matcher"
	"interview/internal/mutation"
	"interview/pkg/specparser"
)

// Engine orchestrates load → match → mutate → detect for a batch run.
type Engine struct {
	registry *mutation.Registry
}

// New creates an engine with the default mutator registry.
func New(registry *mutation.Registry) *Engine {
	if registry == nil {
		registry = mutation.DefaultRegistry()
	}
	return &Engine{registry: registry}
}

// Run executes the full pipeline for the given options.
func (e *Engine) Run(opts config.Options) (domain.RunSummary, error) {
	loadResult, err := loader.LoadDir(opts.RulesDir)
	if err != nil {
		return domain.RunSummary{}, err
	}

	endpoints, err := specparser.ParseSpec(opts.SpecPath)
	if err != nil {
		return domain.RunSummary{}, fmt.Errorf("parse spec: %w", err)
	}

	summary := domain.RunSummary{
		RulesLoaded:  len(loadResult.Rules),
		RulesSkipped: len(loadResult.SkippedFiles),
		SkippedFiles: loadResult.SkippedFiles,
		Warnings:     loadResult.Warnings,
		Endpoints:    len(endpoints),
	}

	for _, ep := range endpoints {
		base := domain.Request{
			Method:  ep.Method,
			Path:    ep.Path,
			Headers: map[string]string{"Authorization": "Bearer demo-token"},
			Query:   map[string]string{},
		}

		for _, rule := range loadResult.Rules {
			if !matcher.Match(rule, ep.Method, ep.Path) {
				continue
			}
			summary.Results = append(summary.Results, e.execute(rule, ep, base))
		}
	}

	return summary, nil
}

func (e *Engine) execute(rule domain.Rule, ep specparser.Endpoint, base domain.Request) domain.ExecutionResult {
	result := domain.ExecutionResult{
		RuleID:           rule.ID,
		RuleName:         rule.Name,
		Severity:         rule.Severity,
		Endpoint:         fmt.Sprintf("%s %s", ep.Method, ep.Path),
		MutationsApplied: rule.Mutations,
	}

	variants, err := e.registry.Apply(base, rule.Mutations)
	if err != nil {
		result.Status = domain.StatusError
		result.Evidence = err.Error()
		return result
	}
	result.Variants = variants

	// Dry-run: no live HTTP. Report mutations and mark detection as skipped,
	// while still recording what criteria would be evaluated.
	result.Status = domain.StatusSkipped
	result.Evidence = fmt.Sprintf(
		"dry-run: generated %d variant(s); detection not evaluated against live HTTP (%s)",
		len(variants),
		formatDetectionCriteria(rule.Detection),
	)
	return result
}

// EvaluateWithResponse is available for future HTTP execution or tests.
func EvaluateWithResponse(rule domain.Rule, resp domain.Response) (domain.ResultStatus, string) {
	matched, evidence := detection.Evaluate(rule.Detection, resp)
	if matched {
		return domain.StatusVulnerable, evidence
	}
	return domain.StatusNotVulnerable, evidence
}

func formatDetectionCriteria(dets []domain.Detection) string {
	if len(dets) == 0 {
		return "no detection criteria"
	}
	parts := make([]string, 0, len(dets))
	for _, d := range dets {
		var conds []string
		if d.StatusCode != 0 {
			conds = append(conds, fmt.Sprintf("status_code=%d", d.StatusCode))
		}
		if d.BodyContains != "" {
			conds = append(conds, fmt.Sprintf("body_contains=%q", d.BodyContains))
		}
		parts = append(parts, strings.Join(conds, " && "))
	}
	return "would match if: " + strings.Join(parts, " OR ")
}
