package governance_test

import (
	"strings"
	"testing"

	"github.com/ScottsSecondAct/governance_as_code_go/governance"
)

// --- shared test helpers (used across combinator, predicate, and priority tests) ---

func alwaysAllow(name string) governance.Policy {
	return governance.Policy{
		Name:    name,
		Version: "1.0",
		Author:  "test",
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectAllow,
				PolicyName: name,
				Reason:     "always allow",
			}
		},
	}
}

func alwaysDeny(name string) governance.Policy {
	return governance.Policy{
		Name:    name,
		Version: "1.0",
		Author:  "test",
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectDeny,
				PolicyName: name,
				Reason:     "always deny",
			}
		},
	}
}

func alwaysAbstain(name string) governance.Policy {
	return governance.Policy{
		Name:    name,
		Version: "1.0",
		Author:  "test",
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return nil
		},
	}
}

func blankCtx() governance.RequestContext {
	return governance.RequestContext{
		Principal:   governance.Principal{ID: "u", Role: "guest"},
		Resource:    governance.Resource{ID: "r", Type: "storage", Classification: "public", Tags: map[string]string{}},
		Action:      governance.Action{Verb: "read"},
		Environment: "dev",
	}
}

func boolPtr(b bool) *bool { return &b }

// --- AllOf tests ---

func TestAllOf(t *testing.T) {
	ctx := blankCtx()
	tests := []struct {
		name       string
		policies   []governance.Policy
		wantAllow  *bool // nil = expect Abstain (nil decision)
		wantReason string
	}{
		{
			name:      "all allow → Allow",
			policies:  []governance.Policy{alwaysAllow("A"), alwaysAllow("B")},
			wantAllow: boolPtr(true),
		},
		{
			name:       "any deny → Deny",
			policies:   []governance.Policy{alwaysAllow("A"), alwaysDeny("B"), alwaysAllow("C")},
			wantAllow:  boolPtr(false),
			wantReason: "B",
		},
		{
			name:      "any abstain → Abstain",
			policies:  []governance.Policy{alwaysAllow("A"), alwaysAbstain("B")},
			wantAllow: nil,
		},
		{
			name:      "zero policies → Allow (vacuous truth)",
			policies:  []governance.Policy{},
			wantAllow: boolPtr(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := governance.AllOf("TestAllOf", tc.policies...)
			d := p.Evaluate(ctx)
			if tc.wantAllow == nil {
				if d != nil {
					t.Errorf("expected Abstain (nil), got %v", d.Effect)
				}
				return
			}
			if d == nil {
				t.Fatalf("expected decision, got Abstain (nil)")
			}
			wantEffect := governance.EffectDeny
			if *tc.wantAllow {
				wantEffect = governance.EffectAllow
			}
			if d.Effect != wantEffect {
				t.Errorf("expected %v, got %v", wantEffect, d.Effect)
			}
			if d.PolicyName != "TestAllOf" {
				t.Errorf("PolicyName: expected TestAllOf, got %q", d.PolicyName)
			}
			if tc.wantReason != "" && !strings.Contains(d.Reason, tc.wantReason) {
				t.Errorf("reason %q does not mention %q", d.Reason, tc.wantReason)
			}
		})
	}
}

func TestAllOfNested(t *testing.T) {
	ctx := blankCtx()
	inner := governance.AnyOf("Inner", alwaysAllow("X"))
	outer := governance.AllOf("Outer", inner, alwaysAllow("Y"))
	d := outer.Evaluate(ctx)
	if d == nil || d.Effect != governance.EffectAllow {
		t.Errorf("nested AllOf(AnyOf(allow), allow): expected Allow, got %v", d)
	}
}

// --- AnyOf tests ---

func TestAnyOf(t *testing.T) {
	ctx := blankCtx()
	tests := []struct {
		name       string
		policies   []governance.Policy
		wantAllow  *bool
		wantReason string
	}{
		{
			name:       "first allow → Allow",
			policies:   []governance.Policy{alwaysAllow("A"), alwaysDeny("B")},
			wantAllow:  boolPtr(true),
			wantReason: "A",
		},
		{
			name:      "all deny → Deny",
			policies:  []governance.Policy{alwaysDeny("A"), alwaysDeny("B")},
			wantAllow: boolPtr(false),
		},
		{
			name:      "all abstain → Abstain",
			policies:  []governance.Policy{alwaysAbstain("A"), alwaysAbstain("B")},
			wantAllow: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := governance.AnyOf("TestAnyOf", tc.policies...)
			d := p.Evaluate(ctx)
			if tc.wantAllow == nil {
				if d != nil {
					t.Errorf("expected Abstain (nil), got %v", d.Effect)
				}
				return
			}
			if d == nil {
				t.Fatalf("expected decision, got Abstain (nil)")
			}
			wantEffect := governance.EffectDeny
			if *tc.wantAllow {
				wantEffect = governance.EffectAllow
			}
			if d.Effect != wantEffect {
				t.Errorf("expected %v, got %v", wantEffect, d.Effect)
			}
			if d.PolicyName != "TestAnyOf" {
				t.Errorf("PolicyName: expected TestAnyOf, got %q", d.PolicyName)
			}
			if tc.wantReason != "" && !strings.Contains(d.Reason, tc.wantReason) {
				t.Errorf("reason %q does not mention %q", d.Reason, tc.wantReason)
			}
		})
	}
}

// --- NoneOf tests ---

func TestNoneOf(t *testing.T) {
	ctx := blankCtx()
	tests := []struct {
		name       string
		policies   []governance.Policy
		wantDeny   *bool // nil = expect Abstain; non-nil true = expect Deny
		wantReason string
	}{
		{
			name:       "any allow → Deny (block-list)",
			policies:   []governance.Policy{alwaysAbstain("A"), alwaysAllow("B")},
			wantDeny:   boolPtr(true),
			wantReason: "B",
		},
		{
			name:     "all abstain → Abstain",
			policies: []governance.Policy{alwaysAbstain("A"), alwaysAbstain("B")},
			wantDeny: nil,
		},
		{
			name:     "all deny → Abstain",
			policies: []governance.Policy{alwaysDeny("A"), alwaysDeny("B")},
			wantDeny: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := governance.NoneOf("TestNoneOf", tc.policies...)
			d := p.Evaluate(ctx)
			if tc.wantDeny == nil {
				if d != nil {
					t.Errorf("expected Abstain (nil), got %v", d.Effect)
				}
				return
			}
			if d == nil {
				t.Fatalf("expected Deny, got Abstain (nil)")
			}
			if d.Effect != governance.EffectDeny {
				t.Errorf("expected Deny, got %v", d.Effect)
			}
			if d.PolicyName != "TestNoneOf" {
				t.Errorf("PolicyName: expected TestNoneOf, got %q", d.PolicyName)
			}
			if tc.wantReason != "" && !strings.Contains(d.Reason, tc.wantReason) {
				t.Errorf("reason %q does not mention %q", d.Reason, tc.wantReason)
			}
		})
	}
}

// --- Integration: combinator in a real PolicyEngine ---

func TestCombinatorInEngine(t *testing.T) {
	engine := &governance.PolicyEngine{}
	engine.RegisterPolicy(governance.AllOf("AllMustAllow",
		alwaysAllow("P1"),
		alwaysAllow("P2"),
	))

	ctx := blankCtx()
	result := engine.Evaluate(ctx)
	if result.Decision.Effect != governance.EffectAllow {
		t.Errorf("AllOf(allow,allow) in engine: expected Allow, got %v", result.Decision.Effect)
	}
	if result.Decision.PolicyName != "AllMustAllow" {
		t.Errorf("PolicyName: expected AllMustAllow, got %q", result.Decision.PolicyName)
	}
	if len(result.Trace.Steps) != 1 {
		t.Errorf("expected 1 step in trace, got %d", len(result.Trace.Steps))
	}
	if result.Trace.Steps[0].Outcome != governance.StepAllow {
		t.Errorf("step outcome: expected Allow, got %v", result.Trace.Steps[0].Outcome)
	}
}
