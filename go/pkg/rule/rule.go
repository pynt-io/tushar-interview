package rule

// Rule is a single attack signature authored in YAML by a security researcher.
type Rule struct {
	ID        string      `yaml:"rule"`
	Name      string      `yaml:"name"`
	Severity  string      `yaml:"severity"`
	Target    Target      `yaml:"target"`
	Mutations []Mutation  `yaml:"mutations"`
	Detection []Detection `yaml:"detection"`
}

// Target describes which endpoints the rule applies to.
type Target struct {
	PathPattern string   `yaml:"path_pattern"`
	Methods     []string `yaml:"methods"`
}

// Mutation describes one transformation of the original request.
type Mutation struct {
	Type     string `yaml:"type"`     // "parameter_swap" | "header_inject"
	Target   string `yaml:"target"`   // "path.userId" | "header.Authorization" | "body.a.b"
	Strategy string `yaml:"strategy"` // parameter_swap: "increment"
	Value    string `yaml:"value"`    // header_inject: the value to set
}

// Detection describes a response pattern that indicates a vulnerability. All set
// conditions must be true for the detection to match.
type Detection struct {
	StatusCode   int    `yaml:"status_code"`
	BodyContains string `yaml:"body_contains"`
}
