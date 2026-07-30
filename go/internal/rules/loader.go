package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	_ "interview/internal/mutate"
)

func LoadRulesFromDir(dir string, recursive bool) ([]Rule, []LoadError, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("rules directory not accessible: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("rules path is not a directory: %s", dir)
	}

	var ruleFiles []string
	if recursive {
		err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				ruleFiles = append(ruleFiles, path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("walking rules directory: %w", err)
		}
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("reading rules directory: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext == ".yaml" || ext == ".yml" {
				ruleFiles = append(ruleFiles, filepath.Join(dir, entry.Name()))
			}
		}
	}

	var loaded []Rule
	var loadErrors []LoadError
	seenIDs := map[string]string{}

	for _, file := range ruleFiles {
		contents, err := os.ReadFile(file)
		if err != nil {
			loadErrors = append(loadErrors, LoadError{File: file, Err: fmt.Errorf("failed to read file: %w", err)})
			continue
		}

		var rule Rule
		if err := yaml.Unmarshal(contents, &rule); err != nil {
			loadErrors = append(loadErrors, LoadError{File: file, Err: fmt.Errorf("invalid YAML: %w", err)})
			continue
		}

		rule.SourceFile = file
		if err := validateRule(&rule, seenIDs); err != nil {
			loadErrors = append(loadErrors, LoadError{File: file, Err: err})
			continue
		}

		seenIDs[rule.ID] = file
		loaded = append(loaded, rule)
	}

	return loaded, loadErrors, nil
}
