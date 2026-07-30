package result

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type Result struct {
	RuleID          string    `json:"rule_id"`
	RuleName        string    `json:"rule_name"`
	Severity        string    `json:"severity"`
	Endpoint        string    `json:"endpoint"`
	Method          string    `json:"method"`
	MutationSummary string    `json:"mutation_summary"`
	ResolvedPath    string    `json:"resolved_path"`
	Status          string    `json:"status"`
	Evidence        Evidence  `json:"evidence,omitempty"`
	Error           string    `json:"error,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

type Evidence struct {
	StatusCode        int      `json:"status_code,omitempty"`
	BodySnippet       string   `json:"body_snippet,omitempty"`
	MatchedConditions []string `json:"matched_conditions,omitempty"`
}

func PrintJSON(results []Result, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func PrintTable(results []Result, w io.Writer) {
	for _, res := range results {
		fmt.Fprintf(w, "%s %s %s %s %s\n", res.RuleID, res.Method, res.Endpoint, res.Status, res.MutationSummary)
	}
}
