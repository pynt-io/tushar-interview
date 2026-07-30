package request

import (
	"net/http"
	"regexp"
	"strings"

	"interview/pkg/specparser"
)

type AttackRequest struct {
	Method          string            `json:"method"`
	PathTemplate    string            `json:"path_template"`
	ResolvedPath    string            `json:"resolved_path"`
	PathParams      map[string]string `json:"path_params,omitempty"`
	QueryParams     map[string]string `json:"query_params,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            []byte            `json:"body,omitempty"`
	IsBaseline      bool              `json:"is_baseline"`
	MutationApplied string            `json:"mutation_applied,omitempty"`
}

var paramRegexp = regexp.MustCompile(`\{([^/{}]+)\}`)

func NewBaselineAttackRequest(endpoint specparser.Endpoint, defaultParamValue string) AttackRequest {
	params := map[string]string{}
	for _, name := range paramNames(endpoint.Path) {
		if _, exists := params[name]; !exists {
			params[name] = defaultParamValue
		}
	}
	resolved := ResolvePath(endpoint.Path, params)
	return AttackRequest{
		Method:          endpoint.Method,
		PathTemplate:    endpoint.Path,
		ResolvedPath:    resolved,
		PathParams:      params,
		QueryParams:     map[string]string{},
		Headers:         map[string]string{},
		Body:            nil,
		IsBaseline:      true,
		MutationApplied: "baseline",
	}
}

func paramNames(pathTemplate string) []string {
	names := []string{}
	for _, match := range paramRegexp.FindAllStringSubmatch(pathTemplate, -1) {
		if len(match) >= 2 {
			names = append(names, match[1])
		}
	}
	return names
}

func ResolvePath(pathTemplate string, params map[string]string) string {
	return paramRegexp.ReplaceAllStringFunc(pathTemplate, func(m string) string {
		name := strings.Trim(m, "{}")
		if value, ok := params[name]; ok {
			return value
		}
		return m
	})
}

func CloneAttackRequest(b AttackRequest) AttackRequest {
	clone := AttackRequest{
		Method:          b.Method,
		PathTemplate:    b.PathTemplate,
		ResolvedPath:    b.ResolvedPath,
		IsBaseline:      b.IsBaseline,
		MutationApplied: b.MutationApplied,
		Body:            nil,
		PathParams:      map[string]string{},
		QueryParams:     map[string]string{},
		Headers:         map[string]string{},
	}
	for k, v := range b.PathParams {
		clone.PathParams[k] = v
	}
	for k, v := range b.QueryParams {
		clone.QueryParams[k] = v
	}
	for k, v := range b.Headers {
		clone.Headers[k] = v
	}
	if len(b.Body) > 0 {
		clone.Body = make([]byte, len(b.Body))
		copy(clone.Body, b.Body)
	}
	return clone
}

func SetHeader(headers map[string]string, key, value string) map[string]string {
	canonical := http.CanonicalHeaderKey(key)
	normalized := map[string]string{}
	for k, v := range headers {
		if http.CanonicalHeaderKey(k) == canonical {
			continue
		}
		normalized[k] = v
	}
	normalized[canonical] = value
	return normalized
}
