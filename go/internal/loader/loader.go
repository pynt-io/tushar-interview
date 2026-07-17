package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"interview/internal/domain"

	"gopkg.in/yaml.v3"
)

// LoadResult holds successfully loaded rules and soft-failure metadata.
type LoadResult struct {
	Rules        []domain.Rule
	SkippedFiles []string
	Warnings     []string
}

// LoadDir reads all .yaml/.yml files in dir. Invalid files are skipped with warnings.
func LoadDir(dir string) (LoadResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return LoadResult{}, fmt.Errorf("read rules directory %s: %w", dir, err)
	}

	var result LoadResult
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, name)
		rule, err := loadFile(path)
		if err != nil {
			result.SkippedFiles = append(result.SkippedFiles, path)
			result.Warnings = append(result.Warnings, fmt.Sprintf("skipping %s: %v", path, err))
			continue
		}
		result.Rules = append(result.Rules, rule)
	}

	if len(result.Rules) == 0 && len(result.SkippedFiles) == 0 {
		return result, fmt.Errorf("no YAML rule files found in %s", dir)
	}
	if len(result.Rules) == 0 {
		return result, fmt.Errorf("no valid rules loaded from %s (%d file(s) skipped)", dir, len(result.SkippedFiles))
	}

	return result, nil
}

func loadFile(path string) (domain.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.Rule{}, fmt.Errorf("read file: %w", err)
	}

	var rule domain.Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return domain.Rule{}, fmt.Errorf("invalid YAML: %w", err)
	}
	rule.SourceFile = path

	if err := validate(rule); err != nil {
		return domain.Rule{}, err
	}
	return rule, nil
}

func validate(rule domain.Rule) error {
	var missing []string
	if strings.TrimSpace(rule.ID) == "" {
		missing = append(missing, "rule")
	}
	if strings.TrimSpace(rule.Name) == "" {
		missing = append(missing, "name")
	}
	if strings.TrimSpace(rule.Target.PathPattern) == "" {
		missing = append(missing, "target.path_pattern")
	}
	if len(rule.Target.Methods) == 0 {
		missing = append(missing, "target.methods")
	}
	if len(rule.Mutations) == 0 {
		missing = append(missing, "mutations")
	}
	for i, m := range rule.Mutations {
		if strings.TrimSpace(m.Type) == "" {
			missing = append(missing, fmt.Sprintf("mutations[%d].type", i))
		}
		if strings.TrimSpace(m.Target) == "" {
			missing = append(missing, fmt.Sprintf("mutations[%d].target", i))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}
