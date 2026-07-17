package mutation_test

import (
	"testing"

	"interview/internal/domain"
	"interview/internal/mutation"
)

func TestParameterSwapIncrement(t *testing.T) {
	t.Parallel()

	m := mutation.ParameterSwap{}
	req := domain.Request{Method: "GET", Path: "/users/{userId}", Headers: map[string]string{}}
	variants, err := m.Apply(req, domain.Mutation{
		Type:     "parameter_swap",
		Target:   "path.userId",
		Strategy: "increment",
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(variants) != 2 {
		t.Fatalf("got %d variants, want 2", len(variants))
	}

	paths := map[string]bool{}
	for _, v := range variants {
		paths[v.Request.Path] = true
		if v.Request.Path == req.Path {
			t.Fatalf("original path was mutated in place: %s", v.Request.Path)
		}
	}
	if !paths["/users/43"] || !paths["/users/41"] {
		t.Fatalf("unexpected paths: %#v", paths)
	}
	if req.Path != "/users/{userId}" {
		t.Fatalf("original request path changed: %s", req.Path)
	}
}

func TestParameterSwapConcretePath(t *testing.T) {
	t.Parallel()

	m := mutation.ParameterSwap{}
	req := domain.Request{Method: "GET", Path: "/users/10"}
	variants, err := m.Apply(req, domain.Mutation{
		Type:     "parameter_swap",
		Target:   "path.userId",
		Strategy: "increment",
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	paths := map[string]bool{}
	for _, v := range variants {
		paths[v.Request.Path] = true
	}
	if !paths["/users/11"] || !paths["/users/9"] {
		t.Fatalf("unexpected paths: %#v", paths)
	}
}

func TestHeaderInject(t *testing.T) {
	t.Parallel()

	m := mutation.HeaderInject{}
	req := domain.Request{
		Method:  "GET",
		Path:    "/admin/dashboard",
		Headers: map[string]string{"Authorization": "Bearer secret"},
	}
	variants, err := m.Apply(req, domain.Mutation{
		Type:   "header_inject",
		Target: "header.Authorization",
		Value:  "",
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(variants) != 1 {
		t.Fatalf("got %d variants, want 1", len(variants))
	}
	if got := variants[0].Request.Headers["Authorization"]; got != "" {
		t.Fatalf("Authorization = %q, want empty", got)
	}
	if req.Headers["Authorization"] != "Bearer secret" {
		t.Fatalf("original headers mutated: %#v", req.Headers)
	}
}

func TestRegistryUnsupportedType(t *testing.T) {
	t.Parallel()

	reg := mutation.DefaultRegistry()
	_, err := reg.Apply(domain.Request{Path: "/"}, []domain.Mutation{{
		Type:   "body_inject",
		Target: "body",
	}})
	if err == nil {
		t.Fatal("expected error for unsupported mutation type")
	}
}
