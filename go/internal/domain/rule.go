package domain

// Rule is a single attack signature loaded from YAML.
type Rule struct {
	ID         string      `yaml:"rule" json:"rule_id"`
	Name       string      `yaml:"name" json:"name"`
	Severity   string      `yaml:"severity" json:"severity"`
	Target     Target      `yaml:"target" json:"target"`
	Mutations  []Mutation  `yaml:"mutations" json:"mutations"`
	Detection  []Detection `yaml:"detection" json:"detection"`
	SourceFile string      `yaml:"-" json:"source_file,omitempty"`
}

// Target describes which endpoints a rule applies to.
type Target struct {
	PathPattern string   `yaml:"path_pattern" json:"path_pattern"`
	Methods     []string `yaml:"methods" json:"methods"`
}

// Mutation describes one request transformation.
type Mutation struct {
	Type     string `yaml:"type" json:"type"`
	Target   string `yaml:"target" json:"target"`
	Strategy string `yaml:"strategy,omitempty" json:"strategy,omitempty"`
	Value    string `yaml:"value,omitempty" json:"value,omitempty"`
}

// Detection describes response conditions that indicate a vulnerability.
// All fields present on an entry must match (AND).
type Detection struct {
	StatusCode   int    `yaml:"status_code" json:"status_code"`
	BodyContains string `yaml:"body_contains,omitempty" json:"body_contains,omitempty"`
}
