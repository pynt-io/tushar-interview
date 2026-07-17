package domain

// ResultStatus is the outcome of evaluating a rule against an endpoint.
type ResultStatus string

const (
	StatusVulnerable    ResultStatus = "vulnerable"
	StatusNotVulnerable ResultStatus = "not_vulnerable"
	StatusSkipped       ResultStatus = "skipped"
	StatusError         ResultStatus = "error"
)

// ExecutionResult is the structured output for one rule × endpoint run.
type ExecutionResult struct {
	RuleID           string           `json:"rule_id"`
	RuleName         string           `json:"rule_name"`
	Severity         string           `json:"severity"`
	Endpoint         string           `json:"endpoint"`
	Status           ResultStatus     `json:"status"`
	MutationsApplied []Mutation       `json:"mutations_applied"`
	Variants         []RequestVariant `json:"variants"`
	Evidence         string           `json:"evidence"`
}

// RunSummary aggregates a full engine run.
type RunSummary struct {
	RulesLoaded  int               `json:"rules_loaded"`
	RulesSkipped int               `json:"rules_skipped"`
	SkippedFiles []string          `json:"skipped_files,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
	Endpoints    int               `json:"endpoints"`
	Results      []ExecutionResult `json:"results"`
}
