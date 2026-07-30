package rules

import (
	"os"
	"path/filepath"
	"testing"

	_ "interview/internal/mutate"
)

func TestLoadRulesFromDir_ValidRule(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `rule: BOLA-001
name: "Broken Object Level Authorization"
severity: high
target:
  path_pattern: "/users/{userId}"
  methods: [GET, PUT]
mutations:
  - type: parameter_swap
    target: path.userId
    strategy: increment
detection:
  - status_code: 200
    body_contains: "email"
`
	path := filepath.Join(dir, "bola.yaml")
	if err := os.WriteFile(path, []byte(ruleContent), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, loadErrors, err := LoadRulesFromDir(dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(loadErrors) != 0 {
		t.Fatalf("expected no load errors, got %d: %v", len(loadErrors), loadErrors)
	}
	if len(rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(rules))
	}
	if rules[0].ID != "BOLA-001" {
		t.Fatalf("expected rule ID BOLA-001, got %s", rules[0].ID)
	}
}

func TestLoadRulesFromDir_InvalidRuleSkipped(t *testing.T) {
	dir := t.TempDir()
	invalid := `rule: BAD-001
name: "Missing target field"
severity: medium
mutations:
  - type: parameter_swap
    target: path.id
    strategy: increment
detection:
  - status_code: 200
`
	path := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, loadErrors, err := LoadRulesFromDir(dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected no loaded rules, got %d", len(rules))
	}
	if len(loadErrors) != 1 {
		t.Fatalf("expected one load error, got %d", len(loadErrors))
	}
	if loadErrors[0].Err.Error() == "" {
		t.Fatal("expected a descriptive load error")
	}
}
