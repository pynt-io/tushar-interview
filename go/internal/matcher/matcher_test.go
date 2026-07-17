package matcher_test

import (
	"testing"

	"interview/internal/domain"
	"interview/internal/matcher"
)

func TestMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		methods []string
		method  string
		path    string
		want    bool
	}{
		{
			name:    "exact template match GET",
			pattern: "/users/{userId}",
			methods: []string{"GET", "PUT"},
			method:  "GET",
			path:    "/users/{userId}",
			want:    true,
		},
		{
			name:    "exact template match PUT",
			pattern: "/users/{userId}",
			methods: []string{"GET", "PUT"},
			method:  "PUT",
			path:    "/users/{userId}",
			want:    true,
		},
		{
			name:    "method not allowed",
			pattern: "/users/{userId}",
			methods: []string{"GET", "PUT"},
			method:  "DELETE",
			path:    "/users/{userId}",
			want:    false,
		},
		{
			name:    "different path",
			pattern: "/users/{userId}",
			methods: []string{"GET"},
			method:  "GET",
			path:    "/products",
			want:    false,
		},
		{
			name:    "wildcard single segment",
			pattern: "/admin/*",
			methods: []string{"GET"},
			method:  "GET",
			path:    "/admin/dashboard",
			want:    true,
		},
		{
			name:    "wildcard does not match deeper path",
			pattern: "/admin/*",
			methods: []string{"GET"},
			method:  "GET",
			path:    "/admin/dashboard/settings",
			want:    false,
		},
		{
			name:    "concrete path matches param pattern",
			pattern: "/users/{userId}",
			methods: []string{"GET"},
			method:  "GET",
			path:    "/users/42",
			want:    true,
		},
		{
			name:    "case insensitive method",
			pattern: "/products",
			methods: []string{"get"},
			method:  "GET",
			path:    "/products",
			want:    true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := domain.Rule{
				Target: domain.Target{
					PathPattern: tt.pattern,
					Methods:     tt.methods,
				},
			}
			got := matcher.Match(rule, tt.method, tt.path)
			if got != tt.want {
				t.Fatalf("Match(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}
