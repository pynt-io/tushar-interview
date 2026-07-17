package loader_test

import (
	"os"
	"path/filepath"
	"testing"

	"interview/internal/loader"
)

func TestLoadDirSkipsInvalid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	valid := []byte(`
rule: OK-001
name: "Valid"
severity: low
target:
  path_pattern: "/ping"
  methods: [GET]
mutations:
  - type: header_inject
    target: header.X-Test
    value: "1"
detection:
  - status_code: 200
`)
	invalid := []byte(`
rule: BAD-001
name: "Missing target"
severity: medium
mutations:
  - type: parameter_swap
    target: path.id
    strategy: increment
detection:
  - status_code: 200
`)
	if err := os.WriteFile(filepath.Join(dir, "ok.yaml"), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), invalid, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(result.Rules) != 1 {
		t.Fatalf("loaded %d rules, want 1", len(result.Rules))
	}
	if result.Rules[0].ID != "OK-001" {
		t.Fatalf("rule id = %s, want OK-001", result.Rules[0].ID)
	}
	if len(result.SkippedFiles) != 1 {
		t.Fatalf("skipped %d, want 1", len(result.SkippedFiles))
	}
}

func TestLoadDirRepoFixtures(t *testing.T) {
	rulesDir := filepath.Join("..", "..", "..", "rules")
	if _, err := os.Stat(rulesDir); err != nil {
		t.Skip("repo rules/ not available:", err)
	}

	result, err := loader.LoadDir(rulesDir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(result.Rules) < 2 {
		t.Fatalf("expected at least 2 valid rules, got %d", len(result.Rules))
	}
	if len(result.SkippedFiles) < 1 {
		t.Fatalf("expected invalid_rule.yaml to be skipped")
	}
}
