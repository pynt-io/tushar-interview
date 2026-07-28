package matcher

import (
	"testing"

	"interview/pkg/rule"
	"interview/pkg/specparser"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		methods []string
		epPath  string
		epMeth  string
		want    bool
	}{
		{"exact path + method", "/users/{userId}", []string{"GET", "PUT"}, "/users/{userId}", "GET", true},
		{"exact path + other listed method", "/users/{userId}", []string{"GET", "PUT"}, "/users/{userId}", "PUT", true},
		{"method not listed", "/users/{userId}", []string{"GET"}, "/users/{userId}", "DELETE", false},
		{"different path", "/users/{userId}", []string{"GET"}, "/products", "GET", false},
		{"param matches concrete-like segment", "/users/{userId}", []string{"GET"}, "/users/{userId}", "GET", true},
		{"wildcard matches one segment", "/admin/*", []string{"GET"}, "/admin/dashboard", "GET", true},
		{"wildcard rejects multiple segments", "/admin/*", []string{"GET"}, "/admin/dashboard/settings", "GET", false},
		{"longer endpoint than pattern", "/users/{userId}", []string{"GET"}, "/users/{userId}/orders", "GET", false},
		{"method case-insensitive", "/products", []string{"get"}, "/products", "GET", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rule.Rule{Target: rule.Target{PathPattern: c.pattern, Methods: c.methods}}
			e := specparser.Endpoint{Path: c.epPath, Method: c.epMeth}
			if got := Match(r, e); got != c.want {
				t.Errorf("Match(%q %v, %s %s) = %v, want %v",
					c.pattern, c.methods, c.epMeth, c.epPath, got, c.want)
			}
		})
	}
}
