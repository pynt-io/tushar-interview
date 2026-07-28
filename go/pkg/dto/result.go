package dto

// Result is the structured outcome of executing one attack variant.
type Result struct {
	RuleID     string
	Endpoint   string
	Mutation   string
	Sent       bool
	Vulnerable bool
	Evidence   string
}
