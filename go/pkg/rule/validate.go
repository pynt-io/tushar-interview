package rule

import (
	"fmt"
	"strings"
)

var knownMethods = map[string]bool{
	"GET": true, "PUT": true, "POST": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

var knownMutationTypes = map[string]bool{
	"parameter_swap": true,
	"header_inject":  true,
}

var knownSwapStrategies = map[string]bool{
	"increment": true,
}

// Validate returns an error describing the first problem found, or nil if the
// rule is well-formed. A rule that fails validation is skipped by the loader so
// that one bad file never aborts the whole run.
func (r *Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("missing 'rule' id")
	}
	if strings.TrimSpace(r.Target.PathPattern) == "" {
		return fmt.Errorf("missing target.path_pattern")
	}
	if len(r.Target.Methods) == 0 {
		return fmt.Errorf("target.methods is empty")
	}
	for _, m := range r.Target.Methods {
		if !knownMethods[strings.ToUpper(m)] {
			return fmt.Errorf("unknown HTTP method %q", m)
		}
	}
	if len(r.Mutations) == 0 {
		return fmt.Errorf("no mutations defined")
	}
	for i, m := range r.Mutations {
		if !knownMutationTypes[m.Type] {
			return fmt.Errorf("mutation[%d]: unknown type %q", i, m.Type)
		}
		if strings.TrimSpace(m.Target) == "" {
			return fmt.Errorf("mutation[%d]: missing target", i)
		}
		if m.Type == "parameter_swap" && !knownSwapStrategies[m.Strategy] {
			return fmt.Errorf("mutation[%d]: parameter_swap requires a known strategy (got %q)", i, m.Strategy)
		}
	}
	return nil
}
