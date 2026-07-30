package matcher

import (
	"testing"

	"interview/internal/rules"
	"interview/pkg/specparser"
)

func TestMatches(t *testing.T) {
	cases := []struct {
		name     string
		rule     rules.Rule
		endpoint specparser.Endpoint
		want     bool
	}{
		{
			name:     "exact path with param matches same endpoint",
			rule:     rules.Rule{Target: rules.Target{PathPattern: "/users/{userId}", Methods: []string{"GET", "PUT"}}},
			endpoint: specparser.Endpoint{Path: "/users/{userId}", Method: "GET"},
			want:     true,
		},
		{
			name:     "exact path with param matches different method",
			rule:     rules.Rule{Target: rules.Target{PathPattern: "/users/{userId}", Methods: []string{"GET", "PUT"}}},
			endpoint: specparser.Endpoint{Path: "/users/{userId}", Method: "PUT"},
			want:     true,
		},
		{
			name:     "different endpoint path does not match",
			rule:     rules.Rule{Target: rules.Target{PathPattern: "/users/{userId}", Methods: []string{"GET"}}},
			endpoint: specparser.Endpoint{Path: "/products", Method: "GET"},
			want:     false,
		},
		{
			name:     "wildcard matches single segment",
			rule:     rules.Rule{Target: rules.Target{PathPattern: "/admin/*", Methods: []string{"GET"}}},
			endpoint: specparser.Endpoint{Path: "/admin/dashboard", Method: "GET"},
			want:     true,
		},
		{
			name:     "wildcard does not match multiple segments",
			rule:     rules.Rule{Target: rules.Target{PathPattern: "/admin/*", Methods: []string{"GET"}}},
			endpoint: specparser.Endpoint{Path: "/admin/dashboard/settings", Method: "GET"},
			want:     false,
		},
		{
			name:     "trailing slash normalized",
			rule:     rules.Rule{Target: rules.Target{PathPattern: "/admin/dashboard/", Methods: []string{"GET"}}},
			endpoint: specparser.Endpoint{Path: "/admin/dashboard", Method: "GET"},
			want:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Matches(tc.rule, tc.endpoint)
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
