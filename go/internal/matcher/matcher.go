package matcher

import (
	"strings"

	"interview/internal/rules"
	"interview/pkg/specparser"
)

type Match struct {
	Rule     rules.Rule
	Endpoint specparser.Endpoint
}

func Matches(rule rules.Rule, endpoint specparser.Endpoint) bool {
	if !methodMatches(rule.Target.Methods, endpoint.Method) {
		return false
	}
	return pathMatches(rule.Target.PathPattern, endpoint.Path)
}

func MatchAll(rulesList []rules.Rule, endpoints []specparser.Endpoint) []Match {
	matches := []Match{}
	for _, rule := range rulesList {
		for _, endpoint := range endpoints {
			if Matches(rule, endpoint) {
				matches = append(matches, Match{Rule: rule, Endpoint: endpoint})
			}
		}
	}
	return matches
}

func methodMatches(allowed []string, actual string) bool {
	actual = strings.ToUpper(strings.TrimSpace(actual))
	for _, method := range allowed {
		if strings.EqualFold(method, actual) {
			return true
		}
	}
	return false
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}

func isParamSegment(segment string) bool {
	return strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
}

func pathMatches(pattern, endpointPath string) bool {
	patternSegments := splitPath(pattern)
	endpointSegments := splitPath(endpointPath)
	if len(patternSegments) != len(endpointSegments) {
		return false
	}

	for i := 0; i < len(patternSegments); i++ {
		p := patternSegments[i]
		e := endpointSegments[i]

		switch {
		case p == "*":
			continue
		case isParamSegment(p) && isParamSegment(e):
			continue
		case p == e:
			continue
		default:
			return false
		}
	}

	return true
}
