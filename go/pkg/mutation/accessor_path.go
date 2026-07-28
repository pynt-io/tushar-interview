package mutation

import "interview/pkg/dto"

// PathAccessor reads and writes path parameter values (stored in
// Request.PathParams, keyed by the placeholder name, e.g. "userId").
type PathAccessor struct{}

func (PathAccessor) Get(r dto.Request, field string) (any, bool) {
	v, ok := r.PathParams[field]
	return v, ok
}

func (PathAccessor) Set(r *dto.Request, field string, val any) {
	if r.PathParams == nil {
		r.PathParams = map[string]string{}
	}
	r.PathParams[field] = toStr(val)
}
