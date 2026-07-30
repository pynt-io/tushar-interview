package rules

import (
	"fmt"
	"strings"

	"interview/internal/mutation"
)

type Rule struct {
	ID         string                 `yaml:"rule"`
	Name       string                 `yaml:"name"`
	Severity   string                 `yaml:"severity"`
	Target     Target                 `yaml:"target"`
	Mutations  []mutation.RawMutation `yaml:"mutations"`
	Detection  []Detection            `yaml:"detection"`
	SourceFile string                 `yaml:"-"`
}

type Target struct {
	PathPattern string   `yaml:"path_pattern"`
	Methods     []string `yaml:"methods"`
}

type Detection struct {
	StatusCode   *int   `yaml:"status_code,omitempty"`
	BodyContains string `yaml:"body_contains,omitempty"`
}

type LoadError struct {
	File string
	Err  error
}

func (e LoadError) Error() string {
	return fmt.Sprintf("%s: %v", e.File, e.Err)
}

func validateRule(rule *Rule, seenIDs map[string]string) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("missing rule id")
	}
	if prev, ok := seenIDs[rule.ID]; ok {
		return fmt.Errorf("duplicate rule id %q (already defined in %s)", rule.ID, prev)
	}
	if strings.TrimSpace(rule.Target.PathPattern) == "" {
		return fmt.Errorf("target.path_pattern is required")
	}
	if len(rule.Target.Methods) == 0 {
		return fmt.Errorf("target.methods must contain at least one HTTP method")
	}

	knownMethods := map[string]bool{
		"GET":     true,
		"PUT":     true,
		"POST":    true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
	}
	for idx, method := range rule.Target.Methods {
		normalized := strings.ToUpper(strings.TrimSpace(method))
		if normalized == "" {
			return fmt.Errorf("target.methods contains an empty method")
		}
		if !knownMethods[normalized] {
			return fmt.Errorf("target.methods contains unsupported method %q", method)
		}
		rule.Target.Methods[idx] = normalized
	}

	if len(rule.Mutations) == 0 {
		return fmt.Errorf("mutations must contain at least one entry")
	}

	for _, mut := range rule.Mutations {
		if strings.TrimSpace(mut.Type) == "" {
			return fmt.Errorf("mutation type is required")
		}
		if !mutation.IsRegistered(mut.Type) {
			return fmt.Errorf("unknown mutation type %q", mut.Type)
		}
		mutator, _ := mutation.Get(mut.Type)
		if mutator != nil {
			if err := mutator.Validate(mut); err != nil {
				return fmt.Errorf("invalid mutation config for %q: %w", mut.Type, err)
			}
		}
	}

	return nil
}
