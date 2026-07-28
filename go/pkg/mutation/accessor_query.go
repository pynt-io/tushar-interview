package mutation

import "interview/pkg/dto"

// QueryAccessor reads and writes query-string parameters. Designed-for: not
// exercised by the two shipped rules, but registered so a rule targeting
// "query.X" works without any engine change.
type QueryAccessor struct{}

func (QueryAccessor) Get(r dto.Request, field string) (any, bool) {
	v, ok := r.Query[field]
	return v, ok
}

func (QueryAccessor) Set(r *dto.Request, field string, val any) {
	if r.Query == nil {
		r.Query = map[string]string{}
	}
	r.Query[field] = toStr(val)
}
