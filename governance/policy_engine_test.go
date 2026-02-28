package governance_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ScottsSecondAct/governance_as_code_go/governance"
)

func makeDefaultEngine() *governance.PolicyEngine {
	return governance.DefaultPolicyEngine()
}

func makeResource(id, resType, classification string, tags map[string]string) governance.Resource {
	if tags == nil {
		tags = map[string]string{}
	}
	return governance.Resource{
		ID:             id,
		Type:           resType,
		Classification: classification,
		Tags:           tags,
	}
}

func TestAdminFullAccess(t *testing.T) {
	engine := makeDefaultEngine()
	restricted := makeResource("r1", "database", "restricted", nil)
	ctx := governance.RequestContext{
		Principal:   governance.Principal{ID: "alice", Role: "admin", Department: "IT"},
		Resource:    restricted,
		Action:      governance.Action{Verb: "delete"},
		Environment: "production",
		MFAVerified: true,
	}

	result := engine.Evaluate(ctx)
	if result.Decision.Effect != governance.EffectAllow {
		t.Errorf("admin delete restricted in prod: expected Allow, got %v", result.Decision.Effect)
	}
	if result.Decision.PolicyName != "AdminFullAccess" {
		t.Errorf("policy name: expected AdminFullAccess, got %q", result.Decision.PolicyName)
	}
}

func TestMFARequiredForRestricted(t *testing.T) {
	engine := makeDefaultEngine()
	restricted := makeResource("r1", "database", "restricted", nil)
	ctx := governance.RequestContext{
		Principal:   governance.Principal{ID: "bob", Role: "engineer", Department: "Backend"},
		Resource:    restricted,
		Action:      governance.Action{Verb: "read"},
		Environment: "staging",
		MFAVerified: false,
	}

	result := engine.Evaluate(ctx)
	if result.Decision.Effect != governance.EffectDeny {
		t.Errorf("engineer read restricted without MFA: expected Deny, got %v", result.Decision.Effect)
	}
	if result.Decision.PolicyName != "MFARequiredForRestricted" {
		t.Errorf("policy name: expected MFARequiredForRestricted, got %q", result.Decision.PolicyName)
	}
}

func TestProductionImmutability(t *testing.T) {
	engine := makeDefaultEngine()
	resource := makeResource("api", "compute", "confidential", nil)

	tests := []struct {
		name        string
		verb        string
		environment string
		wantEffect  governance.Effect
	}{
		{"engineer write prod -> Deny", "write", "production", governance.EffectDeny},
		{"engineer delete prod -> Deny", "delete", "production", governance.EffectDeny},
		{"engineer read prod -> Allow", "read", "production", governance.EffectAllow},
		{"engineer write staging -> Allow", "write", "staging", governance.EffectAllow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := governance.RequestContext{
				Principal:   governance.Principal{ID: "bob", Role: "engineer", Department: "Backend"},
				Resource:    resource,
				Action:      governance.Action{Verb: tc.verb},
				Environment: tc.environment,
				MFAVerified: false,
			}
			result := engine.Evaluate(ctx)
			if result.Decision.Effect != tc.wantEffect {
				t.Errorf("expected %v, got %v", tc.wantEffect, result.Decision.Effect)
			}
		})
	}
}

func TestAnalystReadOnly(t *testing.T) {
	engine := makeDefaultEngine()
	publicRes := makeResource("docs", "storage", "public", map[string]string{"owner": "mktg"})
	confidential := makeResource("db", "database", "confidential", map[string]string{"owner": "bi"})
	restricted := makeResource("vault", "database", "restricted", map[string]string{"owner": "sec"})

	tests := []struct {
		name       string
		resource   governance.Resource
		verb       string
		mfa        bool
		wantEffect governance.Effect
	}{
		{"analyst read public -> Allow", publicRes, "read", false, governance.EffectAllow},
		{"analyst write public -> Deny", publicRes, "write", false, governance.EffectDeny},
		{"analyst read confidential -> Deny", confidential, "read", false, governance.EffectDeny},
		{"analyst read restricted no-MFA -> Deny", restricted, "read", false, governance.EffectDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := governance.RequestContext{
				Principal:   governance.Principal{ID: "carol", Role: "analyst", Department: "DataSci"},
				Resource:    tc.resource,
				Action:      governance.Action{Verb: tc.verb},
				Environment: "dev",
				MFAVerified: tc.mfa,
			}
			result := engine.Evaluate(ctx)
			if result.Decision.Effect != tc.wantEffect {
				t.Errorf("expected %v, got %v", tc.wantEffect, result.Decision.Effect)
			}
		})
	}
}

func TestEngineerAccess(t *testing.T) {
	engine := makeDefaultEngine()
	resource := makeResource("svc", "compute", "internal", map[string]string{"owner": "platform"})

	tests := []struct {
		name        string
		verb        string
		environment string
		wantEffect  governance.Effect
	}{
		{"engineer write dev -> Allow", "write", "dev", governance.EffectAllow},
		{"engineer write staging -> Allow", "write", "staging", governance.EffectAllow},
		{"engineer read prod -> Allow", "read", "production", governance.EffectAllow},
		{"engineer write prod -> Deny", "write", "production", governance.EffectDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := governance.RequestContext{
				Principal:   governance.Principal{ID: "bob", Role: "engineer", Department: "Backend"},
				Resource:    resource,
				Action:      governance.Action{Verb: tc.verb},
				Environment: tc.environment,
				MFAVerified: false,
			}
			result := engine.Evaluate(ctx)
			if result.Decision.Effect != tc.wantEffect {
				t.Errorf("expected %v, got %v", tc.wantEffect, result.Decision.Effect)
			}
		})
	}
}

func TestDefaultDeny(t *testing.T) {
	engine := makeDefaultEngine()
	resource := makeResource("docs", "storage", "public", map[string]string{"owner": "x"})
	ctx := governance.RequestContext{
		Principal:   governance.Principal{ID: "dave", Role: "guest", Department: "Consulting"},
		Resource:    resource,
		Action:      governance.Action{Verb: "read"},
		Environment: "dev",
		MFAVerified: false,
	}

	result := engine.Evaluate(ctx)
	if result.Decision.Effect != governance.EffectDeny {
		t.Errorf("guest read public: expected Deny, got %v", result.Decision.Effect)
	}
	if result.Decision.PolicyName != "default" {
		t.Errorf("policy name: expected default, got %q", result.Decision.PolicyName)
	}
}

func TestEmptyEngine(t *testing.T) {
	engine := &governance.PolicyEngine{}
	resource := makeResource("r", "storage", "public", nil)
	ctx := governance.RequestContext{
		Principal:   governance.Principal{ID: "alice", Role: "admin", Department: "IT"},
		Resource:    resource,
		Action:      governance.Action{Verb: "read"},
		Environment: "dev",
	}

	result := engine.Evaluate(ctx)
	if result.Decision.Effect != governance.EffectDeny {
		t.Errorf("empty engine: expected Deny, got %v", result.Decision.Effect)
	}
}

func TestPolicyCount(t *testing.T) {
	engine := makeDefaultEngine()
	if engine.PolicyCount() != 5 {
		t.Errorf("expected 5 policies, got %d", engine.PolicyCount())
	}
}

func TestEvaluationTrace(t *testing.T) {
	engine := &governance.PolicyEngine{}
	engine.RegisterPolicy(governance.Policy{
		Name:        "AlwaysAbstain",
		Version:     "1.0",
		Author:      "test",
		Description: "Always abstains.",
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return nil
		},
	})
	engine.RegisterPolicy(governance.Policy{
		Name:        "AlwaysAllow",
		Version:     "1.0",
		Author:      "test",
		Description: "Always allows.",
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectAllow,
				PolicyName: "AlwaysAllow",
				Reason:     "Always allowed.",
			}
		},
	})

	ctx := governance.RequestContext{
		Principal:   governance.Principal{ID: "bob", Role: "engineer", Department: "Backend"},
		Resource:    governance.Resource{ID: "r1", Type: "storage", Classification: "public", Tags: map[string]string{}},
		Action:      governance.Action{Verb: "read"},
		Environment: "dev",
	}

	result := engine.Evaluate(ctx)
	if result.Decision.Effect != governance.EffectAllow {
		t.Errorf("expected Allow, got %v", result.Decision.Effect)
	}
	if len(result.Trace.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(result.Trace.Steps))
	}
	if result.Trace.Steps[0].Outcome != governance.StepAbstain {
		t.Errorf("first step: expected Abstain, got %v", result.Trace.Steps[0].Outcome)
	}
	if result.Trace.Steps[1].Outcome != governance.StepAllow {
		t.Errorf("second step: expected Allow, got %v", result.Trace.Steps[1].Outcome)
	}
	if result.Trace.EvaluatedCount() != 1 {
		t.Errorf("evaluated_count: expected 1, got %d", result.Trace.EvaluatedCount())
	}
	if result.Trace.AbstainCount() != 1 {
		t.Errorf("abstain_count: expected 1, got %d", result.Trace.AbstainCount())
	}

	// Single-policy deny engine: trace has 1 step
	denyEngine := &governance.PolicyEngine{}
	denyEngine.RegisterPolicy(governance.Policy{
		Name:        "AlwaysDeny",
		Version:     "1.0",
		Author:      "test",
		Description: "Always denies.",
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision {
			return &governance.PolicyDecision{
				Effect:     governance.EffectDeny,
				PolicyName: "AlwaysDeny",
				Reason:     "Always denied.",
			}
		},
	})

	denyResult := denyEngine.Evaluate(ctx)
	if len(denyResult.Trace.Steps) != 1 {
		t.Errorf("deny trace: expected 1 step, got %d", len(denyResult.Trace.Steps))
	}
	if denyResult.Trace.EvaluatedCount() != 1 {
		t.Errorf("deny evaluated_count: expected 1, got %d", denyResult.Trace.EvaluatedCount())
	}
	if denyResult.Trace.AbstainCount() != 0 {
		t.Errorf("deny abstain_count: expected 0, got %d", denyResult.Trace.AbstainCount())
	}
}

func TestTraceContextPreserved(t *testing.T) {
	engine := makeDefaultEngine()
	ctx := governance.RequestContext{
		Principal:   governance.Principal{ID: "alice@corp.io", Role: "admin", Department: "IT"},
		Resource:    governance.Resource{ID: "db-patient-records", Type: "database", Classification: "restricted", Tags: map[string]string{}},
		Action:      governance.Action{Verb: "read"},
		Environment: "production",
		MFAVerified: true,
	}

	result := engine.Evaluate(ctx)
	if result.Trace.Context.Principal.ID != "alice@corp.io" {
		t.Errorf("trace principal id: expected alice@corp.io, got %q", result.Trace.Context.Principal.ID)
	}
	if result.Trace.Context.Resource.ID != "db-patient-records" {
		t.Errorf("trace resource id: expected db-patient-records, got %q", result.Trace.Context.Resource.ID)
	}
	if result.Trace.Context.Action.Verb != "read" {
		t.Errorf("trace action: expected read, got %q", result.Trace.Context.Action.Verb)
	}
	if result.Trace.Context.Environment != "production" {
		t.Errorf("trace environment: expected production, got %q", result.Trace.Context.Environment)
	}
}

func TestJSONPolicyDecision(t *testing.T) {
	d := governance.PolicyDecision{
		Effect:     governance.EffectAllow,
		PolicyName: "TestPolicy",
		Reason:     "Test reason.",
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(data)
	if !strings.Contains(jsonStr, `"Allow"`) {
		t.Errorf("json missing effect: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"TestPolicy"`) {
		t.Errorf("json missing policy_name: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"Test reason."`) {
		t.Errorf("json missing reason: %s", jsonStr)
	}
}
