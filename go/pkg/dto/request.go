package dto

import "strings"

// Request is a mutable representation of an HTTP request that flows through the
// engine. Path is kept as a template (e.g. "/users/{userId}"); concrete path
// parameter values live in PathParams so accessors can read and modify them
// independently of the template.
type Request struct {
	Method     string
	Path       string            // template, e.g. "/users/{userId}"
	PathParams map[string]string // resolved values, e.g. {"userId": "42"}
	Headers    map[string]string
	Query      map[string]string
	Body       map[string]any // nested JSON
}

// Clone returns a deep copy so that mutation variants never alias the original
// request or each other.
func (r Request) Clone() Request {
	c := Request{
		Method:     r.Method,
		Path:       r.Path,
		PathParams: cloneStringMap(r.PathParams),
		Headers:    cloneStringMap(r.Headers),
		Query:      cloneStringMap(r.Query),
		Body:       cloneAnyMap(r.Body),
	}
	return c
}

// RenderedPath substitutes concrete PathParams into the path template, producing
// the URL path that would actually be sent.
func (r Request) RenderedPath() string {
	p := r.Path
	for k, v := range r.PathParams {
		p = strings.Replace(p, "{"+k+"}", v, 1)
	}
	return p
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func cloneAnyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	c := make(map[string]any, len(m))
	for k, v := range m {
		if nested, ok := v.(map[string]any); ok {
			c[k] = cloneAnyMap(nested)
		} else {
			c[k] = v
		}
	}
	return c
}
