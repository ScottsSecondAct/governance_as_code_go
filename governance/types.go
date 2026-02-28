package governance

// Effect represents a policy decision outcome.
type Effect int

const (
	EffectAllow Effect = iota
	EffectDeny
)

func (e Effect) String() string {
	if e == EffectAllow {
		return "Allow"
	}
	return "Deny"
}

// StepOutcome represents the outcome of a single policy evaluation step.
type StepOutcome int

const (
	StepAllow StepOutcome = iota
	StepDeny
	StepAbstain
)

func (o StepOutcome) String() string {
	switch o {
	case StepAllow:
		return "Allow"
	case StepDeny:
		return "Deny"
	case StepAbstain:
		return "Abstain"
	default:
		return "Unknown"
	}
}

// Principal represents an authenticated subject.
type Principal struct {
	ID         string
	Role       string // "admin", "engineer", "analyst", "guest"
	Department string
}

// Resource represents a governed asset.
type Resource struct {
	ID             string
	Type           string // "database", "storage", "compute", "secret"
	Classification string // "public", "internal", "confidential", "restricted"
	Tags           map[string]string
}

// Action represents an operation to perform.
type Action struct {
	Verb string // "read", "write", "delete", "execute"
}

// RequestContext is the full context for a policy evaluation.
type RequestContext struct {
	Principal   Principal
	Resource    Resource
	Action      Action
	Environment string // "production", "staging", "dev"
	MFAVerified bool
}

// PolicyDecision is the outcome of policy evaluation.
type PolicyDecision struct {
	Effect     Effect `json:"effect"`
	PolicyName string `json:"policy_name"`
	Reason     string `json:"reason"`
}

// PolicyStep records the outcome of a single policy in an evaluation trace.
type PolicyStep struct {
	PolicyName string      `json:"policy"`
	Outcome    StepOutcome `json:"outcome"`
	Reason     string      `json:"reason"`
}

// EvaluationTrace records all policy evaluation steps for an access decision.
type EvaluationTrace struct {
	Context RequestContext
	Steps   []PolicyStep
}

// EvaluatedCount returns the number of steps that were not abstentions.
func (t *EvaluationTrace) EvaluatedCount() int {
	count := 0
	for _, s := range t.Steps {
		if s.Outcome != StepAbstain {
			count++
		}
	}
	return count
}

// AbstainCount returns the number of steps where the policy abstained.
func (t *EvaluationTrace) AbstainCount() int {
	return len(t.Steps) - t.EvaluatedCount()
}

// EvaluationResult pairs a decision with its full evaluation trace.
type EvaluationResult struct {
	Decision PolicyDecision
	Trace    EvaluationTrace
}

// ComplianceReport lists violations found for a resource.
type ComplianceReport struct {
	ResourceID string   `json:"resource_id"`
	Violations []string `json:"violations"`
}

// Compliant returns true when there are no violations.
func (r ComplianceReport) Compliant() bool {
	return len(r.Violations) == 0
}
