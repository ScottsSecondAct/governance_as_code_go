package governance_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ScottsSecondAct/governance_as_code_go/governance"
)

func TestCompliantResources(t *testing.T) {
	checker := governance.DefaultComplianceChecker()
	r := governance.Resource{
		ID:             "db-patient-records",
		Type:           "database",
		Classification: "restricted",
		Tags:           map[string]string{"owner": "health-team"},
	}
	report := checker.Evaluate(r)
	if !report.Compliant() {
		t.Errorf("restricted database with owner tag should be compliant; violations: %v", report.Violations)
	}
	if len(report.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(report.Violations))
	}
	if report.ResourceID != "db-patient-records" {
		t.Errorf("resource id: expected db-patient-records, got %q", report.ResourceID)
	}
}

func TestMissingOwnerTag(t *testing.T) {
	checker := governance.DefaultComplianceChecker()
	r := governance.Resource{
		ID:             "db-no-owner",
		Type:           "storage",
		Classification: "internal",
		Tags:           map[string]string{},
	}
	report := checker.Evaluate(r)
	if report.Compliant() {
		t.Error("missing owner tag should be non-compliant")
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

func TestSecretClassifiedPublic(t *testing.T) {
	checker := governance.DefaultComplianceChecker()

	r := governance.Resource{
		ID:             "secret-api-key",
		Type:           "secret",
		Classification: "public",
		Tags:           map[string]string{"owner": "devops"},
	}
	report := checker.Evaluate(r)
	if report.Compliant() {
		t.Error("public secret should be non-compliant")
	}
	found := false
	for _, v := range report.Violations {
		if strings.Contains(v, "SecretsNotPublic") {
			found = true
		}
	}
	if !found {
		t.Errorf("SecretsNotPublic violation not found in: %v", report.Violations)
	}

	// Non-secret public resource is fine.
	r2 := governance.Resource{
		ID:             "docs",
		Type:           "storage",
		Classification: "public",
		Tags:           map[string]string{"owner": "mktg"},
	}
	report2 := checker.Evaluate(r2)
	if !report2.Compliant() {
		t.Errorf("public storage should be compliant; violations: %v", report2.Violations)
	}
}

func TestDatabasesMustBeRestricted(t *testing.T) {
	checker := governance.DefaultComplianceChecker()

	compliant := governance.Resource{ID: "db-ok", Type: "database", Classification: "restricted", Tags: map[string]string{"owner": "t"}}
	alsoOK := governance.Resource{ID: "db-c", Type: "database", Classification: "confidential", Tags: map[string]string{"owner": "t"}}
	violating := governance.Resource{ID: "db-bad", Type: "database", Classification: "public", Tags: map[string]string{"owner": "t"}}

	if !checker.Evaluate(compliant).Compliant() {
		t.Error("restricted db should be compliant")
	}
	if !checker.Evaluate(alsoOK).Compliant() {
		t.Error("confidential db should be compliant")
	}
	if checker.Evaluate(violating).Compliant() {
		t.Error("public db should be non-compliant")
	}
}

func TestNoUnclassifiedResources(t *testing.T) {
	checker := governance.DefaultComplianceChecker()
	r := governance.Resource{
		ID:             "mystery-box",
		Type:           "storage",
		Classification: "",
		Tags:           map[string]string{"owner": "unknown"},
	}
	report := checker.Evaluate(r)
	if report.Compliant() {
		t.Error("empty classification should be non-compliant")
	}
	found := false
	for _, v := range report.Violations {
		if strings.Contains(v, "NoUnclassifiedResources") {
			found = true
		}
	}
	if !found {
		t.Errorf("NoUnclassifiedResources violation not found in: %v", report.Violations)
	}
}

func TestMultipleViolations(t *testing.T) {
	checker := governance.DefaultComplianceChecker()
	// Missing owner tag + database with public classification.
	rogue := governance.Resource{
		ID:             "db-legacy",
		Type:           "database",
		Classification: "public",
		Tags:           map[string]string{},
	}
	report := checker.Evaluate(rogue)
	if report.Compliant() {
		t.Error("rogue db should be non-compliant")
	}
	if len(report.Violations) != 2 {
		t.Errorf("expected exactly 2 violations (RequiresOwnerTag + DatabasesMustBeRestricted), got %d: %v",
			len(report.Violations), report.Violations)
	}
}

func TestCustomRule(t *testing.T) {
	checker := &governance.ComplianceChecker{}
	checker.AddRule(governance.ComplianceRule{
		Name:        "MustHaveRegionTag",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Resource must specify a 'region' tag.",
		Check: func(r governance.Resource) bool {
			_, ok := r.Tags["region"]
			return ok
		},
	})

	withRegion := governance.Resource{ID: "svc", Type: "compute", Classification: "internal", Tags: map[string]string{"region": "us-east-1"}}
	withoutRegion := governance.Resource{ID: "svc", Type: "compute", Classification: "internal", Tags: map[string]string{}}

	if !checker.Evaluate(withRegion).Compliant() {
		t.Error("resource with region tag should be compliant")
	}
	if checker.Evaluate(withoutRegion).Compliant() {
		t.Error("resource without region tag should be non-compliant")
	}
}

func TestRuleCount(t *testing.T) {
	checker := governance.DefaultComplianceChecker()
	if checker.RuleCount() != 4 {
		t.Errorf("expected 4 rules, got %d", checker.RuleCount())
	}
}

func TestJSONComplianceReport(t *testing.T) {
	checker := governance.DefaultComplianceChecker()
	rogue := governance.Resource{
		ID:             "db-legacy",
		Type:           "database",
		Classification: "public",
		Tags:           map[string]string{},
	}
	report := checker.Evaluate(rogue)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(data)
	if !strings.Contains(jsonStr, `"db-legacy"`) {
		t.Errorf("json missing resource_id: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, "false") {
		t.Errorf("json missing compliant false: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, "violations") {
		t.Errorf("json missing violations key: %s", jsonStr)
	}
}
