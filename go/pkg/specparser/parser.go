package specparser

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Endpoint struct {
	Path        string
	Method      string
	OperationID string
}

func (e Endpoint) String() string {
	return fmt.Sprintf("%s %s", e.Method, e.Path)
}

// ParseSpec parses an OpenAPI 3.x YAML spec file and returns a slice of Endpoints.
//
// Example:
//
//	endpoints, err := specparser.ParseSpec("./sample_specs/petstore.yaml")
//	for _, ep := range endpoints {
//	    fmt.Println(ep) // "GET /users/{userId}"
//	}
func ParseSpec(specPath string) ([]Endpoint, error) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("spec file not found: %s", specPath)
	}

	var spec openAPISpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("invalid YAML in spec: %w", err)
	}

	httpMethods := map[string]bool{
		"get": true, "put": true, "post": true,
		"delete": true, "patch": true,
	}

	var endpoints []Endpoint
	for pathTemplate, methods := range spec.Paths {
		for method, details := range methods {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			ep := Endpoint{
				Path:   pathTemplate,
				Method: strings.ToUpper(method),
			}
			if details != nil {
				ep.OperationID = details.OperationID
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints, nil
}

type openAPISpec struct {
	Paths map[string]map[string]*operationDetails `yaml:"paths"`
}

type operationDetails struct {
	OperationID string `yaml:"operationId"`
	Summary     string `yaml:"summary"`
}
