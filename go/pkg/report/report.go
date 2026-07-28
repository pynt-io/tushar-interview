package report

import (
	"fmt"
	"io"
	"sort"

	"interview/pkg/dto"
)

// PrintAttacks prints the generated attack variants grouped by rule. This is the
// no-send (MVP) output: it proves load -> match -> mutate end-to-end.
func PrintAttacks(w io.Writer, attacks []dto.AttackRequest) {
	if len(attacks) == 0 {
		fmt.Fprintln(w, "\nNo attack requests generated (no rules matched any endpoint).")
		return
	}

	byRule := groupByRule(attacks)
	fmt.Fprintln(w, "\n=== Generated Attack Requests ===")
	for _, id := range sortedKeys(byRule) {
		items := byRule[id]
		fmt.Fprintf(w, "\n%s  %s\n", id, items[0].RuleName)
		for _, a := range items {
			fmt.Fprintf(w, "  %-5s %-24s | %s\n", a.Request.Method, a.Request.RenderedPath(), a.Mutation)
			if len(a.Request.Headers) > 0 {
				fmt.Fprintf(w, "        headers: %v\n", a.Request.Headers)
			}
		}
	}
}

// PrintResults prints detection outcomes, one line per attack variant.
func PrintResults(w io.Writer, results []dto.Result) {
	fmt.Fprintln(w, "\n=== Detection Results ===")
	vulnCount := 0
	for _, r := range results {
		verdict := "safe"
		if r.Vulnerable {
			verdict = "VULNERABLE"
			vulnCount++
		}
		fmt.Fprintf(w, "%-16s %-26s %-11s %s\n", r.RuleID, r.Endpoint, verdict, r.Evidence)
	}
	fmt.Fprintf(w, "\n%d/%d variant(s) flagged vulnerable.\n", vulnCount, len(results))
}

func groupByRule(attacks []dto.AttackRequest) map[string][]dto.AttackRequest {
	m := map[string][]dto.AttackRequest{}
	for _, a := range attacks {
		m[a.RuleID] = append(m[a.RuleID], a)
	}
	return m
}

func sortedKeys(m map[string][]dto.AttackRequest) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
