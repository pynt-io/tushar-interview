package matcher

import (
	"strings"

	"interview/pkg/rule"
	"interview/pkg/specparser"
)

// Match reports whether a rule targets the given endpoint. The endpoint's method
// must appear in the rule's method list AND its path must match the rule's path
// pattern.
func Match(r rule.Rule, e specparser.Endpoint) bool {
	if !containsMethod(r.Target.Methods, e.Method) {
		return false
	}
	return segmentMatch(r.Target.PathPattern, e.Path)
}

func containsMethod(methods []string, method string) bool {
	m := strings.ToUpper(method)
	for _, x := range methods {
		if strings.ToUpper(x) == m {
			return true
		}
	}
	return false
}

// segmentMatch compares two path templates segment-by-segment. A "*" or a
// "{param}" placeholder in the pattern matches exactly one segment; literal
// segments must match exactly. Because the segment counts must be equal, a
// wildcard never spans multiple segments (e.g. "/admin/*" matches
// "/admin/dashboard" but not "/admin/dashboard/settings").
func segmentMatch(pattern, path string) bool {
	p := splitPath(pattern)
	q := splitPath(path)
	if len(p) != len(q) {
		return false
	}
	for i := range p {
		seg := p[i]
		if seg == "*" || isParam(seg) {
			continue
		}
		if seg != q[i] {
			return false
		}
	}
	return true
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func isParam(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}
