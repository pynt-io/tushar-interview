package rule

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRules(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("good.yaml", `
rule: BOLA-001
name: "BOLA"
target:
  path_pattern: "/users/{userId}"
  methods: [GET, PUT]
mutations:
  - type: parameter_swap
    target: path.userId
    strategy: increment
`)
	write("invalid.yaml", `
rule: BAD-001
name: "Missing target field"
mutations:
  - type: parameter_swap
    target: path.id
    strategy: increment
`)
	write("malformed.yaml", "rule: [this is: not valid yaml")

	rules, errs := LoadRules(dir)

	if len(rules) != 1 {
		t.Fatalf("expected 1 valid rule, got %d", len(rules))
	}
	if rules[0].ID != "BOLA-001" {
		t.Errorf("expected BOLA-001, got %q", rules[0].ID)
	}
	if len(errs) != 2 {
		t.Fatalf("expected 2 load errors, got %d: %v", len(errs), errs)
	}
	// methods should be normalized to upper-case
	if rules[0].Target.Methods[0] != "GET" {
		t.Errorf("expected normalized method GET, got %q", rules[0].Target.Methods[0])
	}
}
