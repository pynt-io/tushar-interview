package detect

import (
	"testing"

	"interview/pkg/dto"
	"interview/pkg/rule"
)

func TestDetect(t *testing.T) {
	cases := []struct {
		name       string
		detections []rule.Detection
		resp       dto.Response
		wantVuln   bool
	}{
		{
			"status + body both match",
			[]rule.Detection{{StatusCode: 200, BodyContains: "email"}},
			dto.Response{Status: 200, Body: `{"email":"x@y.com"}`},
			true,
		},
		{
			"status matches but body missing",
			[]rule.Detection{{StatusCode: 200, BodyContains: "email"}},
			dto.Response{Status: 200, Body: `{"id":1}`},
			false,
		},
		{
			"status-only detection",
			[]rule.Detection{{StatusCode: 200}},
			dto.Response{Status: 200, Body: ""},
			true,
		},
		{
			"status mismatch",
			[]rule.Detection{{StatusCode: 200}},
			dto.Response{Status: 403, Body: ""},
			false,
		},
		{
			"empty detection never matches",
			[]rule.Detection{{}},
			dto.Response{Status: 200, Body: "anything"},
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := Detect(c.detections, c.resp)
			if got != c.wantVuln {
				t.Errorf("Detect() = %v, want %v", got, c.wantVuln)
			}
		})
	}
}
