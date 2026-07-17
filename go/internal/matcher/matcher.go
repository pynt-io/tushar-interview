package matcher

import (
	"strings"

	"interview/internal/domain"
)

// Match reports whether rule targets the given method and path.
func Match(rule domain.Rule, method, path string) bool {
	if !methodAllowed(rule.Target.Methods, method) {
		return false
	}
	return pathMatches(rule.Target.PathPattern, path)
}

func methodAllowed(methods []string, method string) bool {
	want := strings.ToUpper(strings.TrimSpace(method))
	for _, m := range methods {
		if strings.ToUpper(strings.TrimSpace(m)) == want {
			return true
		}
	}
	return false
}

// pathMatches compares a rule path pattern to an endpoint path segment-by-segment.
// {param} matches any single segment (including a template segment like {userId}).
// * matches exactly one segment.
func pathMatches(pattern, path string) bool {
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)
	if len(patternParts) != len(pathParts) {
		return false
	}
	for i := range patternParts {
		p := patternParts[i]
		seg := pathParts[i]
		switch {
		case p == "*":
			continue
		case isParam(p):
			continue
		case p == seg:
			continue
		default:
			return false
		}
	}
	return true
}

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func isParam(segment string) bool {
	return strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && len(segment) > 2
}
