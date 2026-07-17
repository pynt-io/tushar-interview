package detection

import (
	"fmt"
	"strings"

	"interview/internal/domain"
)

// Evaluate checks whether any detection entry matches the response.
// A single entry matches when all of its conditions are true (AND).
// Multiple entries are OR'd: any matching entry means vulnerable.
func Evaluate(detections []domain.Detection, resp domain.Response) (matched bool, evidence string) {
	if len(detections) == 0 {
		return false, "no detection criteria defined"
	}

	var failures []string
	for i, d := range detections {
		ok, detail := matchOne(d, resp)
		if ok {
			return true, fmt.Sprintf("detection[%d] matched: %s", i, detail)
		}
		failures = append(failures, fmt.Sprintf("detection[%d]: %s", i, detail))
	}
	return false, "no detection matched (" + strings.Join(failures, "; ") + ")"
}

func matchOne(d domain.Detection, resp domain.Response) (bool, string) {
	if d.StatusCode != 0 && resp.StatusCode != d.StatusCode {
		return false, fmt.Sprintf("status_code want %d got %d", d.StatusCode, resp.StatusCode)
	}

	parts := []string{}
	if d.StatusCode != 0 {
		parts = append(parts, fmt.Sprintf("status_code=%d", resp.StatusCode))
	}

	if d.BodyContains != "" {
		if !strings.Contains(resp.Body, d.BodyContains) {
			return false, fmt.Sprintf("body_contains %q not found", d.BodyContains)
		}
		parts = append(parts, fmt.Sprintf("body_contains=%q", d.BodyContains))
	}

	if len(parts) == 0 {
		return false, "empty detection criteria"
	}
	return true, strings.Join(parts, " && ")
}
