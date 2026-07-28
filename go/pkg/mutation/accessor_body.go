package mutation

import (
	"strings"

	"interview/pkg/dto"
)

// BodyAccessor reads and writes values in a nested JSON body via a dot-path
// (e.g. "user.address.id" descends body["user"]["address"]["id"]). Designed-for:
// demonstrates that nested-payload mutation is isolated entirely inside this
// accessor, so strategies remain oblivious to body structure.
type BodyAccessor struct{}

func (BodyAccessor) Get(r dto.Request, field string) (any, bool) {
	keys := strings.Split(field, ".")
	var cur any = r.Body
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func (BodyAccessor) Set(r *dto.Request, field string, val any) {
	if r.Body == nil {
		r.Body = map[string]any{}
	}
	keys := strings.Split(field, ".")
	m := r.Body
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	m[keys[len(keys)-1]] = val
}
