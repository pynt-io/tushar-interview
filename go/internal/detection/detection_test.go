package detection_test

import (
	"testing"

	"interview/internal/detection"
	"interview/internal/domain"
)

func TestEvaluateANDConditions(t *testing.T) {
	t.Parallel()

	dets := []domain.Detection{{
		StatusCode:   200,
		BodyContains: "email",
	}}

	matched, _ := detection.Evaluate(dets, domain.Response{StatusCode: 200, Body: `{"email":"a@b.c"}`})
	if !matched {
		t.Fatal("expected match when both conditions true")
	}

	matched, _ = detection.Evaluate(dets, domain.Response{StatusCode: 200, Body: `{"id":1}`})
	if matched {
		t.Fatal("expected no match when body_contains missing")
	}

	matched, _ = detection.Evaluate(dets, domain.Response{StatusCode: 403, Body: `{"email":"a@b.c"}`})
	if matched {
		t.Fatal("expected no match when status differs")
	}
}

func TestEvaluateStatusOnly(t *testing.T) {
	t.Parallel()

	dets := []domain.Detection{{StatusCode: 200}}
	matched, evidence := detection.Evaluate(dets, domain.Response{StatusCode: 200, Body: "ok"})
	if !matched {
		t.Fatalf("expected match, evidence=%s", evidence)
	}
}
