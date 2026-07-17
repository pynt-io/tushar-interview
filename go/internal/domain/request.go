package domain

// Request is a mutable HTTP request snapshot used for attack variants.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Query   map[string]string `json:"query,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Clone returns a deep copy so mutations never alter the original.
func (r Request) Clone() Request {
	out := Request{
		Method: r.Method,
		Path:   r.Path,
		Body:   r.Body,
	}
	if r.Headers != nil {
		out.Headers = make(map[string]string, len(r.Headers))
		for k, v := range r.Headers {
			out.Headers[k] = v
		}
	} else {
		out.Headers = make(map[string]string)
	}
	if r.Query != nil {
		out.Query = make(map[string]string, len(r.Query))
		for k, v := range r.Query {
			out.Query[k] = v
		}
	} else {
		out.Query = make(map[string]string)
	}
	return out
}

// RequestVariant is one mutated attack request derived from a rule.
type RequestVariant struct {
	Request        Request           `json:"request"`
	MutationType   string            `json:"mutation_type"`
	Description    string            `json:"description"`
	AppliedDetails map[string]string `json:"applied_details,omitempty"`
}

// Response is an HTTP response used for detection evaluation.
type Response struct {
	StatusCode int
	Body       string
	Headers    map[string]string
}
