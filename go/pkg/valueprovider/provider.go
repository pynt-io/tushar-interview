package valueprovider

// ValueProvider supplies concrete base values for mutation. It fills the gap
// that OpenAPI specs describe templates ("/users/{userId}") but carry no
// concrete values — parameter_swap's increment strategy needs a real number to
// operate on, and body mutations need a real payload to descend into.
type ValueProvider interface {
	// BaseValue returns a starting value for a field in a domain
	// (path / query / header / body).
	BaseValue(domain, field string) any
}

// DefaultProvider returns simple placeholder defaults. This unblocks the MVP;
// future providers (spec examples, a seed-values config, recorded traffic) can
// plug in behind the same interface without touching the engine.
type DefaultProvider struct{}

func (DefaultProvider) BaseValue(domain, field string) any {
	switch domain {
	case "path", "query":
		return 42
	case "body":
		return map[string]any{}
	default:
		return ""
	}
}
