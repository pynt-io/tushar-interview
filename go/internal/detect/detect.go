package detect

import (
	"strings"

	"interview/internal/result"
	"interview/internal/rules"
)

type SimResponse struct {
	StatusCode int
	Body       string
}

func Evaluate(detections []rules.Detection, resp *SimResponse) (bool, result.Evidence) {
	matchedConds := []string{}
	if resp == nil || len(detections) == 0 {
		return false, result.Evidence{}
	}

	for _, det := range detections {
		ok, evidence := evaluateSingle(det, resp)
		if ok {
			return true, evidence
		}
		if len(evidence.MatchedConditions) > 0 {
			matchedConds = append(matchedConds, evidence.MatchedConditions...)
		}
	}

	return false, result.Evidence{StatusCode: resp.StatusCode, BodySnippet: snippet(resp.Body, ""), MatchedConditions: matchedConds}
}

func evaluateSingle(det rules.Detection, resp *SimResponse) (bool, result.Evidence) {
	matched := true
	matchedConds := []string{}

	if det.StatusCode != nil {
		if resp.StatusCode == *det.StatusCode {
			matchedConds = append(matchedConds, "status_code")
		} else {
			matched = false
		}
	}
	if det.BodyContains != "" {
		if strings.Contains(resp.Body, det.BodyContains) {
			matchedConds = append(matchedConds, "body_contains")
		} else {
			matched = false
		}
	}

	evidence := result.Evidence{StatusCode: resp.StatusCode, BodySnippet: snippet(resp.Body, det.BodyContains), MatchedConditions: matchedConds}
	return matched, evidence
}

func snippet(body, substr string) string {
	if substr == "" {
		if len(body) <= 200 {
			return body
		}
		return body[:200]
	}
	idx := strings.Index(body, substr)
	if idx == -1 {
		if len(body) <= 200 {
			return body
		}
		return body[:200]
	}
	start := idx - 20
	if start < 0 {
		start = 0
	}
	end := idx + len(substr) + 20
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}
