package engine_test

import (
	"strings"
	"testing"

	"interview/pkg/detect"
	"interview/pkg/engine"
	"interview/pkg/mocktarget"
	"interview/pkg/rule"
	"interview/pkg/sender"
	"interview/pkg/specparser"
	"interview/pkg/valueprovider"
)

// endpoints mirroring sample_specs/petstore.yaml
func petstoreEndpoints() []specparser.Endpoint {
	return []specparser.Endpoint{
		{Path: "/users/{userId}", Method: "GET"},
		{Path: "/users/{userId}", Method: "PUT"},
		{Path: "/users/{userId}/orders", Method: "GET"},
		{Path: "/admin/dashboard", Method: "GET"},
		{Path: "/admin/users", Method: "GET"},
		{Path: "/products", Method: "GET"},
		{Path: "/products/{productId}", Method: "GET"},
	}
}

func rules() []rule.Rule {
	return []rule.Rule{
		{
			ID: "BOLA-001", Name: "BOLA",
			Target:    rule.Target{PathPattern: "/users/{userId}", Methods: []string{"GET", "PUT"}},
			Mutations: []rule.Mutation{{Type: "parameter_swap", Target: "path.userId", Strategy: "increment"}},
			Detection: []rule.Detection{{StatusCode: 200, BodyContains: "email"}},
		},
		{
			ID: "AUTH-BYPASS-001", Name: "Auth Bypass",
			Target:    rule.Target{PathPattern: "/admin/*", Methods: []string{"GET"}},
			Mutations: []rule.Mutation{{Type: "header_inject", Target: "header.Authorization", Value: ""}},
			Detection: []rule.Detection{{StatusCode: 200}},
		},
	}
}

func TestEngineGeneratesExpectedAttacks(t *testing.T) {
	attacks, warnings := engine.Run(rules(), petstoreEndpoints(), valueprovider.DefaultProvider{})
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	// BOLA matches GET+PUT /users/{userId} -> 2 endpoints x 2 variants = 4
	// AUTH matches GET /admin/dashboard and GET /admin/users -> 2 endpoints x 1 = 2
	if len(attacks) != 6 {
		t.Fatalf("expected 6 attack requests, got %d", len(attacks))
	}

	// spot-check that /users/{userId}/orders and /products did NOT match BOLA
	for _, a := range attacks {
		if strings.Contains(a.Endpoint, "orders") || strings.Contains(a.Endpoint, "products") {
			t.Errorf("unexpected match against %q", a.Endpoint)
		}
	}
}

func TestEngineEndToEndWithMockTarget(t *testing.T) {
	attacks, _ := engine.Run(rules(), petstoreEndpoints(), valueprovider.DefaultProvider{})

	srv := mocktarget.New()
	defer srv.Close()

	responses := sender.Send(attacks, srv.URL, 5)
	results := detect.Correlate(attacks, responses, rules())

	// every generated variant should be flagged vulnerable against the
	// deliberately-vulnerable mock target
	for _, r := range results {
		if !r.Vulnerable {
			t.Errorf("expected %s @ %s to be vulnerable, got safe (%s)", r.RuleID, r.Endpoint, r.Evidence)
		}
	}
	if len(results) != 6 {
		t.Fatalf("expected 6 results, got %d", len(results))
	}
}
