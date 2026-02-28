package governance_test

import (
	"testing"

	"github.com/ScottsSecondAct/governance_as_code_go/governance"
)

func TestHighPriorityEvaluatedFirst(t *testing.T) {
	engine := &governance.PolicyEngine{}
	// Register low-priority first, high-priority second — sort must reorder them.
	engine.RegisterPolicy(governance.Policy{
		Name:     "LowPriority",
		Priority: 0,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectAllow,
				PolicyName: "LowPriority",
				Reason:     "low priority allow",
			}
		},
	})
	engine.RegisterPolicy(governance.Policy{
		Name:     "HighPriority",
		Priority: 10,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectDeny,
				PolicyName: "HighPriority",
				Reason:     "high priority deny",
			}
		},
	})

	ctx := blankCtx()
	result := engine.Evaluate(ctx)
	// HighPriority should run first and short-circuit with Deny.
	if result.Decision.Effect != governance.EffectDeny {
		t.Errorf("expected Deny from HighPriority, got %v", result.Decision.Effect)
	}
	if result.Decision.PolicyName != "HighPriority" {
		t.Errorf("expected HighPriority policy, got %q", result.Decision.PolicyName)
	}
	if len(result.Trace.Steps) != 1 {
		t.Errorf("expected 1 trace step (short-circuited), got %d", len(result.Trace.Steps))
	}
	if result.Trace.Steps[0].PolicyName != "HighPriority" {
		t.Errorf("first step should be HighPriority, got %q", result.Trace.Steps[0].PolicyName)
	}
}

func TestSamePriorityPreservesRegistrationOrder(t *testing.T) {
	engine := &governance.PolicyEngine{}
	// Both priority 0 — stable sort must preserve registration order.
	engine.RegisterPolicy(governance.Policy{
		Name:     "First",
		Priority: 0,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectAllow,
				PolicyName: "First",
				Reason:     "first allow",
			}
		},
	})
	engine.RegisterPolicy(governance.Policy{
		Name:     "Second",
		Priority: 0,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectAllow,
				PolicyName: "Second",
				Reason:     "second allow",
			}
		},
	})

	ctx := blankCtx()
	result := engine.Evaluate(ctx)
	// First registered wins when priority ties.
	if result.Decision.PolicyName != "First" {
		t.Errorf("same priority: expected First to win, got %q", result.Decision.PolicyName)
	}
	if result.Trace.Steps[0].PolicyName != "First" {
		t.Errorf("first step should be First, got %q", result.Trace.Steps[0].PolicyName)
	}
}

func TestNegativePriorityEvaluatedLast(t *testing.T) {
	engine := &governance.PolicyEngine{}
	// NegativePriority registered first, but must appear last in trace.
	engine.RegisterPolicy(governance.Policy{
		Name:     "NegativePriority",
		Priority: -1,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return nil // abstain — just to verify trace order
		},
	})
	engine.RegisterPolicy(governance.Policy{
		Name:     "ZeroPriority",
		Priority: 0,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectAllow,
				PolicyName: "ZeroPriority",
				Reason:     "zero priority allow",
			}
		},
	})

	ctx := blankCtx()
	result := engine.Evaluate(ctx)
	// ZeroPriority runs first and provides the Allow decision.
	if result.Decision.PolicyName != "ZeroPriority" {
		t.Errorf("zero priority should win over negative, got %q", result.Decision.PolicyName)
	}
	// Trace must show ZeroPriority before NegativePriority.
	if len(result.Trace.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(result.Trace.Steps))
	}
	if result.Trace.Steps[0].PolicyName != "ZeroPriority" {
		t.Errorf("step 0 should be ZeroPriority, got %q", result.Trace.Steps[0].PolicyName)
	}
	if result.Trace.Steps[1].PolicyName != "NegativePriority" {
		t.Errorf("step 1 should be NegativePriority, got %q", result.Trace.Steps[1].PolicyName)
	}
}

func TestHighPriorityDenyShortCircuits(t *testing.T) {
	engine := &governance.PolicyEngine{}
	engine.RegisterPolicy(governance.Policy{
		Name:     "LowAllow",
		Priority: 1,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectAllow,
				PolicyName: "LowAllow",
				Reason:     "low allow",
			}
		},
	})
	engine.RegisterPolicy(governance.Policy{
		Name:     "HighDeny",
		Priority: 100,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectDeny,
				PolicyName: "HighDeny",
				Reason:     "high deny",
			}
		},
	})

	ctx := blankCtx()
	result := engine.Evaluate(ctx)
	if result.Decision.Effect != governance.EffectDeny {
		t.Errorf("high priority deny should short-circuit, got %v", result.Decision.Effect)
	}
	if len(result.Trace.Steps) != 1 {
		t.Errorf("expected 1 step (short-circuited), got %d", len(result.Trace.Steps))
	}
}

func TestDefaultPolicyEngineRegressionWithPriority(t *testing.T) {
	// All DefaultPolicyEngine policies have Priority 0; stable sort is a no-op.
	engine := governance.DefaultPolicyEngine()

	adminCtx := governance.RequestContext{
		Principal:   governance.Principal{ID: "alice", Role: "admin"},
		Resource:    governance.Resource{ID: "r", Type: "database", Classification: "restricted", Tags: map[string]string{}},
		Action:      governance.Action{Verb: "delete"},
		Environment: "production",
		MFAVerified: true,
	}
	result := engine.Evaluate(adminCtx)
	if result.Decision.Effect != governance.EffectAllow {
		t.Errorf("regression: admin should still Allow, got %v", result.Decision.Effect)
	}
	if result.Decision.PolicyName != "AdminFullAccess" {
		t.Errorf("regression: expected AdminFullAccess, got %q", result.Decision.PolicyName)
	}

	engineerCtx := governance.RequestContext{
		Principal:   governance.Principal{ID: "bob", Role: "engineer"},
		Resource:    governance.Resource{ID: "svc", Type: "compute", Classification: "internal", Tags: map[string]string{}},
		Action:      governance.Action{Verb: "write"},
		Environment: "production",
	}
	result = engine.Evaluate(engineerCtx)
	if result.Decision.Effect != governance.EffectDeny {
		t.Errorf("regression: engineer write in prod should Deny, got %v", result.Decision.Effect)
	}
}
