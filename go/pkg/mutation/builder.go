package mutation

import (
	"strings"

	"interview/pkg/dto"
	"interview/pkg/specparser"
	"interview/pkg/valueprovider"
)

// FromEndpoint builds the original (un-mutated) request for an endpoint. The
// path stays as a template; each "{param}" gets a concrete base value from the
// ValueProvider, stored in PathParams for accessors to read and modify.
func FromEndpoint(ep specparser.Endpoint, vp valueprovider.ValueProvider) dto.Request {
	pathParams := map[string]string{}
	for _, seg := range strings.Split(strings.Trim(ep.Path, "/"), "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(seg, "{"), "}")
			pathParams[name] = toStr(vp.BaseValue("path", name))
		}
	}
	return dto.Request{
		Method:     ep.Method,
		Path:       ep.Path,
		PathParams: pathParams,
		Headers:    map[string]string{},
		Query:      map[string]string{},
		Body:       map[string]any{},
	}
}
