package mutate

import (
	"fmt"
	"strconv"
	"strings"

	"interview/internal/mutation"
	"interview/internal/request"
)

type parameterSwapMutator struct{}

type paramSwapConfig struct {
	Target   string `yaml:"target"`
	Strategy string `yaml:"strategy"`
}

func init() {
	mutation.MustRegister(parameterSwapMutator{})
}

func (parameterSwapMutator) Type() string {
	return "parameter_swap"
}

func (parameterSwapMutator) Validate(m mutation.RawMutation) error {
	var cfg paramSwapConfig
	if err := m.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid parameter_swap config: %w", err)
	}
	if strings.TrimSpace(cfg.Target) == "" {
		return fmt.Errorf("target is required")
	}
	if cfg.Strategy != "increment" {
		return fmt.Errorf("unsupported strategy %q", cfg.Strategy)
	}
	if !strings.HasPrefix(cfg.Target, "path.") {
		return fmt.Errorf("target must be path.<paramName>")
	}
	paramName := strings.TrimPrefix(cfg.Target, "path.")
	if strings.TrimSpace(paramName) == "" {
		return fmt.Errorf("path mutation target must include a parameter name")
	}
	return nil
}

func (parameterSwapMutator) Apply(baseline request.AttackRequest, m mutation.RawMutation) ([]request.AttackRequest, error) {
	var cfg paramSwapConfig
	if err := m.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid parameter_swap config: %w", err)
	}

	paramName := strings.TrimPrefix(cfg.Target, "path.")
	current, ok := baseline.PathParams[paramName]
	if !ok {
		return nil, fmt.Errorf("path parameter %q not present in endpoint template", paramName)
	}

	originalValue := strings.TrimSpace(current)
	id, err := strconv.Atoi(originalValue)
	if err != nil {
		return nil, fmt.Errorf("parameter_swap increment requires numeric path param %q, got %q", paramName, originalValue)
	}

	variants := make([]request.AttackRequest, 0, 2)
	for _, delta := range []int{1, -1} {
		mutated := request.CloneAttackRequest(baseline)
		mutated.IsBaseline = false
		mutated.PathParams[paramName] = strconv.Itoa(id + delta)
		mutated.ResolvedPath = request.ResolvePath(mutated.PathTemplate, mutated.PathParams)
		mutated.MutationApplied = fmt.Sprintf("%s: %d -> %d", paramName, id, id+delta)
		variants = append(variants, mutated)
	}

	return variants, nil
}
