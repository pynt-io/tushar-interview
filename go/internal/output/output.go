package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"interview/internal/domain"
)

// WriteJSON prints the full run summary as indented JSON.
func WriteJSON(w io.Writer, summary domain.RunSummary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

// WriteHuman prints a concise human-readable summary plus JSON results.
func WriteHuman(w io.Writer, summary domain.RunSummary, warnings []string) error {
	for _, warn := range warnings {
		fmt.Fprintf(w, "WARNING: %s\n", warn)
	}
	if len(warnings) > 0 {
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Loaded %d rule(s), skipped %d invalid file(s), scanned %d endpoint(s), produced %d result(s)\n\n",
		summary.RulesLoaded, summary.RulesSkipped, summary.Endpoints, len(summary.Results))

	for i, r := range summary.Results {
		fmt.Fprintf(w, "[%d] %s (%s) on %s → %s\n", i+1, r.RuleID, r.Severity, r.Endpoint, r.Status)
		fmt.Fprintf(w, "    name: %s\n", r.RuleName)
		for _, v := range r.Variants {
			fmt.Fprintf(w, "    variant: %s %s", v.Request.Method, v.Request.Path)
			if len(v.Request.Headers) > 0 && v.MutationType == "header_inject" {
				fmt.Fprintf(w, " headers=%v", v.Request.Headers)
			}
			fmt.Fprintf(w, " (%s)\n", v.Description)
		}
		fmt.Fprintf(w, "    evidence: %s\n\n", r.Evidence)
	}

	fmt.Fprintln(w, "--- JSON ---")
	return WriteJSON(w, summary)
}

// FormatWarnings joins loader warnings for display.
func FormatWarnings(warnings []string) string {
	return strings.Join(warnings, "\n")
}
