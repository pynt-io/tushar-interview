package executor

import (
    "path/filepath"
    "testing"

    "interview/internal/rules"
    "interview/pkg/specparser"
)

func TestRun_GeneratesExpectedResults(t *testing.T) {
    rulesDir := filepath.Join("..", "..", "..", "rules")
    specPath := filepath.Join("..", "..", "..", "sample_specs", "petstore.yaml")

    loadedRules, loadErrors, err := rules.LoadRulesFromDir(rulesDir, false)
    if err != nil {
        t.Fatalf("failed to load rules: %v", err)
    }
    if len(loadErrors) != 1 {
        t.Fatalf("expected one load error from invalid rule, got %d", len(loadErrors))
    }

    endpoints, err := specparser.ParseSpec(specPath)
    if err != nil {
        t.Fatalf("failed to parse spec: %v", err)
    }

    results := Run(loadedRules, endpoints, RunOptions{SendRequests: false, DefaultPathParamValue: "42"})
    if len(results) != 6 {
        t.Fatalf("expected 6 generated results, got %d", len(results))
    }
    for _, res := range results {
        if res.Status != "generated_not_sent" {
            t.Fatalf("expected status generated_not_sent, got %q", res.Status)
        }
    }
}
