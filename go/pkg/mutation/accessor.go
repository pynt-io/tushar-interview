package mutation

import (
	"strings"

	"interview/pkg/dto"
)

// Accessor reads and writes a value at a field path within one request domain
// (path / query / header / body). It is the "where" axis of a mutation, kept
// orthogonal to the "what" axis (Mutator) so that domains and strategies compose
// instead of multiplying.
type Accessor interface {
	Get(r dto.Request, field string) (any, bool)
	Set(r *dto.Request, field string, val any)
}

var accessorRegistry = map[string]Accessor{
	"path":   PathAccessor{},
	"header": HeaderAccessor{},
	"query":  QueryAccessor{},
	"body":   BodyAccessor{},
}

// AccessorFor returns the accessor registered for a domain, or nil if unknown.
func AccessorFor(domain string) Accessor {
	return accessorRegistry[domain]
}

// ParseTarget splits a mutation target into its domain and field path, e.g.
// "body.user.address.id" -> ("body", "user.address.id"),
// "header.Authorization" -> ("header", "Authorization").
func ParseTarget(target string) (domain, field string) {
	parts := strings.SplitN(target, ".", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}
