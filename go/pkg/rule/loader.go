package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadError records a rule file that could not be loaded, so one bad file never
// aborts the run — the engine reports these and continues with the valid rules.
type LoadError struct {
	File string
	Err  error
}

func (e LoadError) Error() string {
	return fmt.Sprintf("%s: %v", filepath.Base(e.File), e.Err)
}

// LoadRules reads every *.yaml / *.yml file in dir, unmarshals and validates
// each, and returns the valid rules plus a slice of load errors describing the
// ones that were skipped.
func LoadRules(dir string) ([]Rule, []LoadError) {
	var rules []Rule
	var loadErrs []LoadError

	var files []string
	for _, pattern := range []string{"*.yaml", "*.yml"} {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		files = append(files, matches...)
	}

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			loadErrs = append(loadErrs, LoadError{File: f, Err: err})
			continue
		}

		var r Rule
		if err := yaml.Unmarshal(raw, &r); err != nil {
			loadErrs = append(loadErrs, LoadError{File: f, Err: fmt.Errorf("invalid YAML: %w", err)})
			continue
		}

		// Normalize HTTP methods to upper-case for consistent matching.
		for i, m := range r.Target.Methods {
			r.Target.Methods[i] = strings.ToUpper(m)
		}

		if err := r.Validate(); err != nil {
			loadErrs = append(loadErrs, LoadError{File: f, Err: err})
			continue
		}

		rules = append(rules, r)
	}

	return rules, loadErrs
}
