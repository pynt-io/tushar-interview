package dto

// AttackRequest wraps a single mutated Request with provenance, so every
// downstream response and result maps back to the rule and endpoint that
// produced it. Carrying the lineage inside each unit of work (rather than in
// shared state) also makes concurrent sending trivially safe.
type AttackRequest struct {
	RuleID   string
	RuleName string
	Endpoint string // "GET /users/{userId}"
	Mutation string // human description, e.g. "parameter_swap increment on path.userId"
	Request  Request
}
