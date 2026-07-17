package mutation

import (
	"fmt"
	"strings"

	"interview/internal/domain"
)

// HeaderInject sets or replaces an HTTP header on a cloned request.
type HeaderInject struct{}

func (HeaderInject) Type() string { return "header_inject" }

func (HeaderInject) Apply(req domain.Request, m domain.Mutation) ([]domain.RequestVariant, error) {
	headerName, err := parseHeaderTarget(m.Target)
	if err != nil {
		return nil, err
	}

	cloned := req.Clone()
	prev, had := cloned.Headers[headerName]
	cloned.Headers[headerName] = m.Value

	desc := fmt.Sprintf("set header %s=%q", headerName, m.Value)
	if had {
		desc = fmt.Sprintf("replace header %s %q -> %q", headerName, prev, m.Value)
	}

	return []domain.RequestVariant{{
		Request:      cloned,
		MutationType: "header_inject",
		Description:  desc,
		AppliedDetails: map[string]string{
			"header": headerName,
			"value":  m.Value,
		},
	}}, nil
}

func parseHeaderTarget(target string) (string, error) {
	const prefix = "header."
	if !strings.HasPrefix(target, prefix) {
		return "", fmt.Errorf("header_inject target must be header.<Name>, got %q", target)
	}
	name := strings.TrimPrefix(target, prefix)
	if name == "" {
		return "", fmt.Errorf("header_inject target missing header name")
	}
	return name, nil
}
