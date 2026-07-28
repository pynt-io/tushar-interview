package mutation

import (
	"testing"

	"interview/pkg/dto"
	"interview/pkg/rule"
	"interview/pkg/specparser"
	"interview/pkg/valueprovider"
)

var vp = valueprovider.DefaultProvider{}

func TestParameterSwapIncrement(t *testing.T) {
	orig := FromEndpoint(specparser.Endpoint{Path: "/users/{userId}", Method: "GET"}, vp)
	m := rule.Mutation{Type: "parameter_swap", Target: "path.userId", Strategy: "increment"}

	variants, err := ParameterSwap{}.Mutate(orig, PathAccessor{}, "userId", m, vp)
	if err != nil {
		t.Fatal(err)
	}
	if len(variants) != 2 {
		t.Fatalf("expected 2 variants, got %d", len(variants))
	}

	got := []string{variants[0].RenderedPath(), variants[1].RenderedPath()}
	want := map[string]bool{"/users/43": true, "/users/41": true}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected variant path %q (want /users/43 and /users/41)", g)
		}
	}

	// original must be untouched
	if orig.RenderedPath() != "/users/42" {
		t.Errorf("original was mutated: %q", orig.RenderedPath())
	}
}

func TestHeaderInjectAddAndReplace(t *testing.T) {
	m := rule.Mutation{Type: "header_inject", Target: "header.Authorization", Value: ""}

	// add when absent
	orig := dto.Request{Method: "GET", Path: "/admin/dashboard", Headers: map[string]string{}}
	variants, err := HeaderInject{}.Mutate(orig, HeaderAccessor{}, "Authorization", m, vp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := variants[0].Headers["Authorization"]; !ok || v != "" {
		t.Errorf("expected Authorization set to empty, got %q (present=%v)", v, ok)
	}

	// replace when present (case-insensitive)
	orig2 := dto.Request{Method: "GET", Path: "/admin/dashboard", Headers: map[string]string{"authorization": "Bearer xyz"}}
	variants2, _ := HeaderInject{}.Mutate(orig2, HeaderAccessor{}, "Authorization", m, vp)
	if variants2[0].Headers["authorization"] != "" {
		t.Errorf("expected existing header replaced with empty, got %q", variants2[0].Headers["authorization"])
	}
}

func TestBodyAccessorNested(t *testing.T) {
	r := dto.Request{Body: map[string]any{}}
	acc := BodyAccessor{}

	acc.Set(&r, "user.address.id", 7)
	got, ok := acc.Get(r, "user.address.id")
	if !ok || got != 7 {
		t.Errorf("nested body set/get failed: got %v ok=%v", got, ok)
	}

	// missing intermediate returns not-found, not a panic
	if _, ok := acc.Get(r, "user.missing.id"); ok {
		t.Error("expected missing nested path to report not-found")
	}
}

func TestParseTarget(t *testing.T) {
	cases := map[string][2]string{
		"path.userId":          {"path", "userId"},
		"header.Authorization": {"header", "Authorization"},
		"body.user.address.id": {"body", "user.address.id"},
		"bareword":             {"bareword", ""},
	}
	for in, want := range cases {
		d, f := ParseTarget(in)
		if d != want[0] || f != want[1] {
			t.Errorf("ParseTarget(%q) = (%q,%q), want (%q,%q)", in, d, f, want[0], want[1])
		}
	}
}
