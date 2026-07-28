package detect

import (
	"fmt"
	"strings"

	"interview/pkg/dto"
	"interview/pkg/rule"
)

// Detect reports whether a response matches any of the rule's detection
// signatures. A single detection matches only when ALL of its set conditions
// hold (status_code and/or body_contains).
func Detect(detections []rule.Detection, resp dto.Response) (bool, string) {
	for _, d := range detections {
		if matches(d, resp) {
			return true, evidence(d, resp)
		}
	}
	return false, ""
}

func matches(d rule.Detection, resp dto.Response) bool {
	// A detection with no conditions set never matches, to avoid false positives.
	if d.StatusCode == 0 && d.BodyContains == "" {
		return false
	}
	if d.StatusCode != 0 && resp.Status != d.StatusCode {
		return false
	}
	if d.BodyContains != "" && !strings.Contains(resp.Body, d.BodyContains) {
		return false
	}
	return true
}

func evidence(d rule.Detection, resp dto.Response) string {
	parts := []string{fmt.Sprintf("status=%d", resp.Status)}
	if d.BodyContains != "" {
		parts = append(parts, fmt.Sprintf("body contains %q", d.BodyContains))
	}
	return strings.Join(parts, ", ")
}
