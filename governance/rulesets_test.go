package governance_test

import (
	"strings"
	"testing"

	"github.com/ScottsSecondAct/governance_as_code_go/governance"
)

func TestAddRuleSetPrefixesViolations(t *testing.T) {
	checker := &governance.ComplianceChecker{}
	checker.AddRuleSet(governance.SOC2RuleSet())

	noOwner := governance.Resource{
		ID:             "svc",
		Type:           "storage",
		Classification: "internal",
		Tags:           map[string]string{},
	}
	report := checker.Evaluate(noOwner)
	found := false
	for _, v := range report.Violations {
		if strings.Contains(v, "SOC2/RequiresOwnerTag") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SOC2/RequiresOwnerTag in violations, got: %v", report.Violations)
	}
}

func TestAddRuleSetDoesNotMutateOriginal(t *testing.T) {
	rs := governance.SOC2RuleSet()
	originalName := rs.Rules[0].Name // "RequiresOwnerTag"
	checker := &governance.ComplianceChecker{}
	checker.AddRuleSet(rs)
	if rs.Rules[0].Name != originalName {
		t.Errorf("AddRuleSet mutated original RuleSet: expected %q, got %q", originalName, rs.Rules[0].Name)
	}
}

func TestAddRulesNoPrefixing(t *testing.T) {
	checker := &governance.ComplianceChecker{}
	checker.AddRules(governance.SOC2RuleSet().Rules)

	noOwner := governance.Resource{
		ID:             "svc",
		Type:           "storage",
		Classification: "internal",
		Tags:           map[string]string{},
	}
	report := checker.Evaluate(noOwner)
	found := false
	for _, v := range report.Violations {
		if strings.Contains(v, "RequiresOwnerTag") && !strings.Contains(v, "SOC2/") {
			found = true
		}
	}
	if !found {
		t.Errorf("AddRules should preserve raw name (no SOC2/ prefix): %v", report.Violations)
	}
}

func TestRuleCountAfterAddRuleSet(t *testing.T) {
	checker := &governance.ComplianceChecker{}
	checker.AddRuleSet(governance.SOC2RuleSet())        // 2 rules
	checker.AddRuleSet(governance.DataSecurityRuleSet()) // 2 rules
	if checker.RuleCount() != 4 {
		t.Errorf("expected 4 rules after 2 AddRuleSet calls, got %d", checker.RuleCount())
	}
}

func TestDefaultComplianceCheckerViolationFormatUnchanged(t *testing.T) {
	checker := governance.DefaultComplianceChecker()
	noOwner := governance.Resource{
		ID:             "svc",
		Type:           "storage",
		Classification: "internal",
		Tags:           map[string]string{},
	}
	report := checker.Evaluate(noOwner)
	for _, v := range report.Violations {
		if strings.Contains(v, "SOC2/") {
			t.Errorf("DefaultComplianceChecker should not produce SOC2/ prefix: %q", v)
		}
	}
	found := false
	for _, v := range report.Violations {
		if strings.Contains(v, "RequiresOwnerTag") {
			found = true
		}
	}
	if !found {
		t.Errorf("RequiresOwnerTag violation not found in: %v", report.Violations)
	}
}

func TestDataSecurityRuleSet(t *testing.T) {
	checker := &governance.ComplianceChecker{}
	checker.AddRuleSet(governance.DataSecurityRuleSet())

	publicSecret := governance.Resource{
		ID:             "key",
		Type:           "secret",
		Classification: "public",
		Tags:           map[string]string{"owner": "ops"},
	}
	report := checker.Evaluate(publicSecret)
	found := false
	for _, v := range report.Violations {
		if strings.Contains(v, "DataSecurity/SecretsNotPublic") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DataSecurity/SecretsNotPublic in violations, got: %v", report.Violations)
	}
}
