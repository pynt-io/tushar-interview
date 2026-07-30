package mutation

import (
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
	"interview/internal/request"
)

type RawMutation struct {
	Type string               `yaml:"type"`
	Raw  map[string]yaml.Node `yaml:",inline"`
}

type Mutator interface {
	Type() string
	Validate(m RawMutation) error
	Apply(baseline request.AttackRequest, m RawMutation) ([]request.AttackRequest, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Mutator{}
)

func Register(m Mutator) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[m.Type()] = m
}

func Get(t string) (Mutator, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	m, ok := registry[t]
	return m, ok
}

func IsRegistered(t string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[t]
	return ok
}

func KnownTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	types := make([]string, 0, len(registry))
	for t := range registry {
		types = append(types, t)
	}
	return types
}

func MustRegister(m Mutator) {
	if m == nil {
		panic("cannot register nil mutator")
	}
	if m.Type() == "" {
		panic("mutator Type() must be non-empty")
	}
	Register(m)
}

func (m RawMutation) Decode(out interface{}) error {
	data, err := yaml.Marshal(m.Raw)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, out)
}

func RequireStringField(node yaml.Node, name string) (string, error) {
	var raw struct {
		Value *string `yaml:"value"`
	}
	if err := node.Decode(&raw); err != nil {
		return "", fmt.Errorf("failed to decode %s: %w", name, err)
	}
	if raw.Value == nil {
		return "", fmt.Errorf("missing required field %q", name)
	}
	return *raw.Value, nil
}
