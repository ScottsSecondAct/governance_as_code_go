package governance

import "encoding/json"

// MarshalJSON serializes Effect as its string name ("Allow" or "Deny").
func (e Effect) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

// MarshalJSON serializes StepOutcome as its string name.
func (o StepOutcome) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

// MarshalJSON serializes EvaluationResult with the trace context flattened
// to match the C++ json.hpp output shape exactly.
func (r EvaluationResult) MarshalJSON() ([]byte, error) {
	type traceJSON struct {
		Principal   string       `json:"principal"`
		Resource    string       `json:"resource"`
		Action      string       `json:"action"`
		Environment string       `json:"environment"`
		Steps       []PolicyStep `json:"steps"`
	}

	steps := r.Trace.Steps
	if steps == nil {
		steps = []PolicyStep{}
	}

	return json.Marshal(struct {
		Decision PolicyDecision `json:"decision"`
		Trace    traceJSON      `json:"trace"`
	}{
		Decision: r.Decision,
		Trace: traceJSON{
			Principal:   r.Trace.Context.Principal.ID,
			Resource:    r.Trace.Context.Resource.ID,
			Action:      r.Trace.Context.Action.Verb,
			Environment: r.Trace.Context.Environment,
			Steps:       steps,
		},
	})
}

// MarshalJSON serializes ComplianceReport with a computed "compliant" field.
func (r ComplianceReport) MarshalJSON() ([]byte, error) {
	violations := r.Violations
	if violations == nil {
		violations = []string{}
	}
	return json.Marshal(struct {
		ResourceID string   `json:"resource_id"`
		Compliant  bool     `json:"compliant"`
		Violations []string `json:"violations"`
	}{
		ResourceID: r.ResourceID,
		Compliant:  r.Compliant(),
		Violations: violations,
	})
}
