package mutate

import (
	"testing"

	"gopkg.in/yaml.v3"
	"interview/internal/mutation"
	"interview/internal/request"
	"interview/pkg/specparser"
)

func TestParameterSwapProduceVariants(t *testing.T) {
	baseline := request.NewBaselineAttackRequest(specparser.Endpoint{Path: "/users/{userId}", Method: "GET"}, "42")
	mutator, ok := mutation.Get("parameter_swap")
	if !ok {
		t.Fatal("parameter_swap mutator not registered")
	}

	variants, err := mutator.Apply(baseline, mutation.RawMutation{Type: "parameter_swap", Raw: yamlNode(`target: path.userId
strategy: increment
`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(variants) != 2 {
		t.Fatalf("expected 2 variants, got %d", len(variants))
	}
	if variants[0].ResolvedPath != "/users/43" && variants[1].ResolvedPath != "/users/43" {
		t.Fatalf("expected one variant to resolve to /users/43, got %v and %v", variants[0].ResolvedPath, variants[1].ResolvedPath)
	}
	if variants[0].MutationApplied == "" || variants[1].MutationApplied == "" {
		t.Fatal("expected mutation summary to be set")
	}
}

func TestParameterSwapNonNumericFails(t *testing.T) {
	baseline := request.NewBaselineAttackRequest(specparser.Endpoint{Path: "/users/{userId}", Method: "GET"}, "foo")
	mutator, ok := mutation.Get("parameter_swap")
	if !ok {
		t.Fatal("parameter_swap mutator not registered")
	}

	_, err := mutator.Apply(baseline, mutation.RawMutation{Type: "parameter_swap", Raw: yamlNode(`target: path.userId
strategy: increment
`)})
	if err == nil {
		t.Fatal("expected error for non-numeric path param")
	}
}

func TestHeaderInjectAddsHeader(t *testing.T) {
	baseline := request.NewBaselineAttackRequest(specparser.Endpoint{Path: "/admin/dashboard", Method: "GET"}, "42")
	mutator, ok := mutation.Get("header_inject")
	if !ok {
		t.Fatal("header_inject mutator not registered")
	}

	variants, err := mutator.Apply(baseline, mutation.RawMutation{Type: "header_inject", Raw: yamlNode(`target: header.Authorization
value: ""
`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(variants) != 1 {
		t.Fatalf("expected 1 variant, got %d", len(variants))
	}
	if variants[0].Headers["Authorization"] != "" {
		t.Fatalf("expected Authorization header to be set to empty string, got %q", variants[0].Headers["Authorization"])
	}
}

func yamlNode(yamlText string) map[string]yaml.Node {
	var node map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(yamlText), &node); err != nil {
		panic(err)
	}
	return node
}
