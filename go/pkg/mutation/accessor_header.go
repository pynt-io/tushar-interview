package mutation

import (
	"strings"

	"interview/pkg/dto"
)

// HeaderAccessor reads and writes HTTP headers case-insensitively. Set replaces
// an existing header (matched case-insensitively) or adds it if absent.
type HeaderAccessor struct{}

func (HeaderAccessor) Get(r dto.Request, field string) (any, bool) {
	for k, v := range r.Headers {
		if strings.EqualFold(k, field) {
			return v, true
		}
	}
	return nil, false
}

func (HeaderAccessor) Set(r *dto.Request, field string, val any) {
	if r.Headers == nil {
		r.Headers = map[string]string{}
	}
	for k := range r.Headers {
		if strings.EqualFold(k, field) {
			r.Headers[k] = toStr(val)
			return
		}
	}
	r.Headers[field] = toStr(val)
}
