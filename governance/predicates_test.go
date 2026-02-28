package governance_test

import (
	"testing"

	"github.com/ScottsSecondAct/governance_as_code_go/governance"
)

func TestWhenPredicateTrue(t *testing.T) {
	wrapped := alwaysAllow("WrappedAllow")
	p := governance.When(func(_ governance.RequestContext) bool { return true }, wrapped)
	d := p.Evaluate(blankCtx())
	if d == nil || d.Effect != governance.EffectAllow {
		t.Errorf("predicate true: expected Allow, got %v", d)
	}
}

func TestWhenPredicateFalse(t *testing.T) {
	wrapped := alwaysAllow("WrappedAllow")
	p := governance.When(func(_ governance.RequestContext) bool { return false }, wrapped)
	d := p.Evaluate(blankCtx())
	if d != nil {
		t.Errorf("predicate false: expected Abstain (nil), got %v", d.Effect)
	}
}

func TestWhenInheritsNameAndPriority(t *testing.T) {
	wrapped := governance.Policy{
		Name:     "InheritedName",
		Priority: 42,
		Evaluate: func(_ governance.RequestContext) *governance.PolicyDecision { return nil },
	}
	p := governance.When(func(_ governance.RequestContext) bool { return true }, wrapped)
	if p.Name != "InheritedName" {
		t.Errorf("Name: expected InheritedName, got %q", p.Name)
	}
	if p.Priority != 42 {
		t.Errorf("Priority: expected 42, got %d", p.Priority)
	}
}

func TestWhenAbstainsInStaging(t *testing.T) {
	engine := &governance.PolicyEngine{}
	engine.RegisterPolicy(governance.When(
		governance.InEnvironment("production"),
		governance.ProductionImmutability(),
	))
	engine.RegisterPolicy(alwaysAllow("FallbackAllow"))

	stagingCtx := governance.RequestContext{
		Principal:   governance.Principal{ID: "bob", Role: "engineer"},
		Resource:    governance.Resource{ID: "svc", Type: "compute", Classification: "internal", Tags: map[string]string{}},
		Action:      governance.Action{Verb: "write"},
		Environment: "staging",
	}
	result := engine.Evaluate(stagingCtx)
	if result.Decision.Effect != governance.EffectAllow {
		t.Errorf("When(InEnvironment(production)) in staging: expected Allow (abstain+fallback), got %v", result.Decision.Effect)
	}
}

func TestWhenFiresInProduction(t *testing.T) {
	engine := &governance.PolicyEngine{}
	engine.RegisterPolicy(governance.When(
		governance.InEnvironment("production"),
		governance.ProductionImmutability(),
	))
	engine.RegisterPolicy(alwaysAllow("FallbackAllow"))

	prodCtx := governance.RequestContext{
		Principal:   governance.Principal{ID: "bob", Role: "engineer"},
		Resource:    governance.Resource{ID: "svc", Type: "compute", Classification: "internal", Tags: map[string]string{}},
		Action:      governance.Action{Verb: "write"},
		Environment: "production",
	}
	result := engine.Evaluate(prodCtx)
	if result.Decision.Effect != governance.EffectDeny {
		t.Errorf("When(InEnvironment(production)) write in production: expected Deny, got %v", result.Decision.Effect)
	}
}

func TestInEnvironment(t *testing.T) {
	prod := governance.InEnvironment("production")
	multi := governance.InEnvironment("dev", "staging")

	tests := []struct {
		name      string
		predicate func(governance.RequestContext) bool
		env       string
		want      bool
	}{
		{"production matches production", prod, "production", true},
		{"production does not match dev", prod, "dev", false},
		{"multi matches dev", multi, "dev", true},
		{"multi matches staging", multi, "staging", true},
		{"multi does not match production", multi, "production", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := governance.RequestContext{Environment: tc.env}
			got := tc.predicate(ctx)
			if got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestForResourceType(t *testing.T) {
	isDB := governance.ForResourceType("database")
	isDBOrSecret := governance.ForResourceType("database", "secret")

	tests := []struct {
		name      string
		predicate func(governance.RequestContext) bool
		resType   string
		want      bool
	}{
		{"database matches database", isDB, "database", true},
		{"database does not match storage", isDB, "storage", false},
		{"multi matches secret", isDBOrSecret, "secret", true},
		{"multi matches database", isDBOrSecret, "database", true},
		{"multi does not match storage", isDBOrSecret, "storage", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := governance.RequestContext{Resource: governance.Resource{Type: tc.resType}}
			got := tc.predicate(ctx)
			if got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestForRole(t *testing.T) {
	isAdmin := governance.ForRole("admin")
	isAdminOrEngineer := governance.ForRole("admin", "engineer")

	tests := []struct {
		name      string
		predicate func(governance.RequestContext) bool
		role      string
		want      bool
	}{
		{"admin matches admin", isAdmin, "admin", true},
		{"admin does not match guest", isAdmin, "guest", false},
		{"multi matches engineer", isAdminOrEngineer, "engineer", true},
		{"multi matches admin", isAdminOrEngineer, "admin", true},
		{"multi does not match guest", isAdminOrEngineer, "guest", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := governance.RequestContext{Principal: governance.Principal{Role: tc.role}}
			got := tc.predicate(ctx)
			if got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
