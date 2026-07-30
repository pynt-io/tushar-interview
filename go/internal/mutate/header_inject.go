package mutate

import (
	"fmt"
	"strings"

	"interview/internal/mutation"
	"interview/internal/request"
)

type headerInjectMutator struct{}

type headerInjectConfig struct {
	Target string  `yaml:"target"`
	Value  *string `yaml:"value"`
}

func init() {
	mutation.MustRegister(headerInjectMutator{})
}

func (headerInjectMutator) Type() string {
	return "header_inject"
}

func (headerInjectMutator) Validate(m mutation.RawMutation) error {
	var cfg headerInjectConfig
	if err := m.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid header_inject config: %w", err)
	}
	if strings.TrimSpace(cfg.Target) == "" {
		return fmt.Errorf("target is required")
	}
	if !strings.HasPrefix(cfg.Target, "header.") {
		return fmt.Errorf("target must be header.<HeaderName>")
	}
	headerName := strings.TrimPrefix(cfg.Target, "header.")
	if strings.TrimSpace(headerName) == "" {
		return fmt.Errorf("header target must include a header name")
	}
	if cfg.Value == nil {
		return fmt.Errorf("value field is required")
	}
	return nil
}

func (headerInjectMutator) Apply(baseline request.AttackRequest, m mutation.RawMutation) ([]request.AttackRequest, error) {
	var cfg headerInjectConfig
	if err := m.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid header_inject config: %w", err)
	}

	headerName := strings.TrimPrefix(cfg.Target, "header.")
	value := ""
	if cfg.Value != nil {
		value = *cfg.Value
	}

	mutated := request.CloneAttackRequest(baseline)
	mutated.IsBaseline = false
	mutated.Headers = request.SetHeader(mutated.Headers, headerName, value)
	mutated.MutationApplied = fmt.Sprintf("header %s set to %q", headerName, value)
	return []request.AttackRequest{mutated}, nil
}
