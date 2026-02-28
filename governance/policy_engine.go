package governance

import "sort"

// PolicyFn is a function that evaluates a policy against a request context.
// Returns nil to abstain (no opinion).
type PolicyFn func(RequestContext) *PolicyDecision

// Policy is a named rule with metadata and an evaluation function.
type Policy struct {
	Name        string
	Version     string
	Author      string
	Description string
	Priority    int // Higher values evaluated first. Default 0. Ties preserve registration order.
	Evaluate    PolicyFn
}

// PolicyEngine evaluates an ordered list of policies against a RequestContext.
//
// Resolution strategy (fail-closed):
//  1. First explicit Deny wins immediately.
//  2. If at least one Allow and no Deny, access is granted.
//  3. Default: Deny if no policy explicitly allows.
type PolicyEngine struct {
	policies []Policy
}

// RegisterPolicy appends a policy to the engine's evaluation list.
// Policies are sorted by Priority descending; ties preserve registration order.
func (e *PolicyEngine) RegisterPolicy(p Policy) {
	e.policies = append(e.policies, p)
	sort.SliceStable(e.policies, func(i, j int) bool {
		return e.policies[i].Priority > e.policies[j].Priority
	})
}

// PolicyCount returns the number of registered policies.
func (e *PolicyEngine) PolicyCount() int {
	return len(e.policies)
}

// Evaluate runs all registered policies against ctx and returns the result.
func (e *PolicyEngine) Evaluate(ctx RequestContext) EvaluationResult {
	trace := EvaluationTrace{
		Context: ctx,
		Steps:   []PolicyStep{},
	}
	var firstAllow *PolicyDecision

	for _, policy := range e.policies {
		decision := policy.Evaluate(ctx)
		if decision == nil {
			trace.Steps = append(trace.Steps, PolicyStep{
				PolicyName: policy.Name,
				Outcome:    StepAbstain,
				Reason:     "",
			})
			continue
		}

		if decision.Effect == EffectDeny {
			trace.Steps = append(trace.Steps, PolicyStep{
				PolicyName: policy.Name,
				Outcome:    StepDeny,
				Reason:     decision.Reason,
			})
			return EvaluationResult{Decision: *decision, Trace: trace}
		}

		trace.Steps = append(trace.Steps, PolicyStep{
			PolicyName: policy.Name,
			Outcome:    StepAllow,
			Reason:     decision.Reason,
		})
		if firstAllow == nil {
			firstAllow = decision
		}
	}

	if firstAllow != nil {
		return EvaluationResult{Decision: *firstAllow, Trace: trace}
	}

	defaultDeny := PolicyDecision{
		Effect:     EffectDeny,
		PolicyName: "default",
		Reason:     "No policy explicitly granted access.",
	}
	return EvaluationResult{Decision: defaultDeny, Trace: trace}
}
