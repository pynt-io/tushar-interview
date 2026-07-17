package mutation

import (
	"fmt"
	"strconv"
	"strings"

	"interview/internal/domain"
)

const defaultParamValue = 42

// ParameterSwap replaces a path parameter using a strategy (e.g. increment).
type ParameterSwap struct{}

func (ParameterSwap) Type() string { return "parameter_swap" }

func (ParameterSwap) Apply(req domain.Request, m domain.Mutation) ([]domain.RequestVariant, error) {
	paramName, err := parsePathTarget(m.Target)
	if err != nil {
		return nil, err
	}

	strategy := strings.ToLower(strings.TrimSpace(m.Strategy))
	if strategy == "" {
		strategy = "increment"
	}
	if strategy != "increment" {
		return nil, fmt.Errorf("unsupported parameter_swap strategy %q", m.Strategy)
	}

	baseValue, resolvedPath, err := resolveParamValue(req.Path, paramName)
	if err != nil {
		return nil, err
	}

	deltas := []int{1, -1}
	variants := make([]domain.RequestVariant, 0, len(deltas))
	for _, delta := range deltas {
		newVal := baseValue + delta
		cloned := req.Clone()
		cloned.Path = replacePathParam(resolvedPath, paramName, strconv.Itoa(newVal))
		variants = append(variants, domain.RequestVariant{
			Request:      cloned,
			MutationType: "parameter_swap",
			Description:  fmt.Sprintf("swap path.%s %d -> %d", paramName, baseValue, newVal),
			AppliedDetails: map[string]string{
				"param":    paramName,
				"strategy": strategy,
				"from":     strconv.Itoa(baseValue),
				"to":       strconv.Itoa(newVal),
			},
		})
	}
	return variants, nil
}

func parsePathTarget(target string) (string, error) {
	const prefix = "path."
	if !strings.HasPrefix(target, prefix) {
		return "", fmt.Errorf("parameter_swap target must be path.<name>, got %q", target)
	}
	name := strings.TrimPrefix(target, prefix)
	if name == "" {
		return "", fmt.Errorf("parameter_swap target missing parameter name")
	}
	return name, nil
}

// resolveParamValue finds the concrete numeric value for a named path param.
// Template paths like /users/{userId} are materialized with a demo value (42).
func resolveParamValue(path, paramName string) (int, string, error) {
	parts := splitPath(path)
	placeholder := "{" + paramName + "}"

	for i, part := range parts {
		if part == placeholder {
			resolved := make([]string, len(parts))
			copy(resolved, parts)
			resolved[i] = strconv.Itoa(defaultParamValue)
			return defaultParamValue, "/" + strings.Join(resolved, "/"), nil
		}
		if isParam(part) {
			continue
		}
		// Named param may already be concrete if path was previously resolved
		// by position: match by scanning for {paramName} only above.
	}

	// If the path is a template with a differently-named param in the same
	// position as the rule's target, still try exact placeholder match first.
	// Fall back: if path has a concrete numeric segment where {paramName}
	// would be relative to a known template... For OpenAPI templates we already
	// handled {paramName}. For concrete paths like /users/42, locate the segment
	// after matching surrounding literals is not available here — use heuristic:
	// find first concrete numeric segment when a single path param exists.
	numericIdx := -1
	paramCount := 0
	for i, part := range parts {
		if isParam(part) {
			paramCount++
			continue
		}
		if _, err := strconv.Atoi(part); err == nil {
			numericIdx = i
		}
	}
	if numericIdx >= 0 && paramCount == 0 {
		n, _ := strconv.Atoi(parts[numericIdx])
		return n, path, nil
	}

	return 0, "", fmt.Errorf("could not resolve path parameter %q in %q", paramName, path)
}

func replacePathParam(path, paramName, newValue string) string {
	parts := splitPath(path)
	placeholder := "{" + paramName + "}"
	for i, part := range parts {
		if part == placeholder {
			parts[i] = newValue
			return joinPath(parts)
		}
	}
	// Concrete path: replace the numeric segment we previously resolved.
	// Prefer replacing a segment equal to the old demo/base if present;
	// otherwise replace the first numeric segment.
	for i, part := range parts {
		if _, err := strconv.Atoi(part); err == nil {
			parts[i] = newValue
			return joinPath(parts)
		}
	}
	return path
}

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func joinPath(parts []string) string {
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func isParam(segment string) bool {
	return strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && len(segment) > 2
}
