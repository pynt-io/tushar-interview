package rule

import "testing"

func validRule() Rule {
	return Rule{
		ID:     "R-1",
		Target: Target{PathPattern: "/users/{userId}", Methods: []string{"GET"}},
		Mutations: []Mutation{
			{Type: "parameter_swap", Target: "path.userId", Strategy: "increment"},
		},
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Rule)
		wantErr bool
	}{
		{"valid rule", func(*Rule) {}, false},
		{"missing id", func(r *Rule) { r.ID = "" }, true},
		{"missing path pattern", func(r *Rule) { r.Target.PathPattern = "" }, true},
		{"empty methods", func(r *Rule) { r.Target.Methods = nil }, true},
		{"unknown method", func(r *Rule) { r.Target.Methods = []string{"FETCH"} }, true},
		{"no mutations", func(r *Rule) { r.Mutations = nil }, true},
		{"unknown mutation type", func(r *Rule) { r.Mutations[0].Type = "sql_inject" }, true},
		{"missing mutation target", func(r *Rule) { r.Mutations[0].Target = "" }, true},
		{"bad swap strategy", func(r *Rule) { r.Mutations[0].Strategy = "double" }, true},
		{"header_inject needs no strategy", func(r *Rule) {
			r.Mutations[0] = Mutation{Type: "header_inject", Target: "header.Authorization", Value: ""}
		}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := validRule()
			c.mutate(&r)
			err := r.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
