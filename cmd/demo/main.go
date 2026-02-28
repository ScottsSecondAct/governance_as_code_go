package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ScottsSecondAct/governance_as_code_go/governance"
)

func effectStr(e governance.Effect) string {
	if e == governance.EffectAllow {
		return "[ALLOW]"
	}
	return "[DENY] "
}

func outcomeStr(o governance.StepOutcome) string {
	switch o {
	case governance.StepAllow:
		return "Allow  "
	case governance.StepDeny:
		return "Deny   "
	case governance.StepAbstain:
		return "Abstain"
	default:
		return "Unknown"
	}
}

func printDecision(ctx governance.RequestContext, d governance.PolicyDecision) {
	mfa := ""
	if ctx.MFAVerified {
		mfa = " [MFA]"
	}
	fmt.Printf("\n  Principal : %s [%s]\n", ctx.Principal.ID, ctx.Principal.Role)
	fmt.Printf("  Resource  : %s (%s)\n", ctx.Resource.ID, ctx.Resource.Classification)
	fmt.Printf("  Action    : %s @ %s%s\n", ctx.Action.Verb, ctx.Environment, mfa)
	fmt.Printf("  Decision  : %s <- %s\n", effectStr(d.Effect), d.PolicyName)
	fmt.Printf("  Reason    : %s\n", d.Reason)
}

func printTrace(trace governance.EvaluationTrace) {
	fmt.Println("  Steps:")
	for _, step := range trace.Steps {
		if step.Reason != "" {
			fmt.Printf("    [%s] %s -- %s\n", outcomeStr(step.Outcome), step.PolicyName, step.Reason)
		} else {
			fmt.Printf("    [%s] %s\n", outcomeStr(step.Outcome), step.PolicyName)
		}
	}
}

func separator(title string) {
	bar := strings.Repeat("-", 55)
	fmt.Printf("\n%s\n  %s\n%s\n", bar, title, bar)
}

func main() {
	// Build Policy Engine.
	engine := governance.DefaultPolicyEngine()

	// Define Resources.
	patientDB := governance.Resource{
		ID:             "db-patient-records",
		Type:           "database",
		Classification: "restricted",
		Tags:           map[string]string{"owner": "health-team", "region": "us-west-2"},
	}
	publicDocs := governance.Resource{
		ID:             "storage-public-docs",
		Type:           "storage",
		Classification: "public",
		Tags:           map[string]string{"owner": "marketing"},
	}
	prodAPI := governance.Resource{
		ID:             "compute-prod-api",
		Type:           "compute",
		Classification: "confidential",
		Tags:           map[string]string{"env": "production", "owner": "platform-team"},
	}

	// Define Principals.
	alice := governance.Principal{ID: "alice@corp.io", Role: "admin", Department: "IT"}
	bob := governance.Principal{ID: "bob@corp.io", Role: "engineer", Department: "Backend"}
	carol := governance.Principal{ID: "carol@corp.io", Role: "analyst", Department: "DataSci"}
	dave := governance.Principal{ID: "dave@corp.io", Role: "guest", Department: "Consulting"}

	// Access Control Scenarios.
	separator("ACCESS CONTROL EVALUATION")

	scenarios := []governance.RequestContext{
		{Principal: alice, Resource: patientDB, Action: governance.Action{Verb: "read"}, Environment: "production", MFAVerified: true},
		{Principal: bob, Resource: prodAPI, Action: governance.Action{Verb: "write"}, Environment: "production", MFAVerified: false},
		{Principal: bob, Resource: prodAPI, Action: governance.Action{Verb: "read"}, Environment: "production", MFAVerified: false},
		{Principal: bob, Resource: prodAPI, Action: governance.Action{Verb: "write"}, Environment: "staging", MFAVerified: false},
		{Principal: carol, Resource: publicDocs, Action: governance.Action{Verb: "read"}, Environment: "dev", MFAVerified: false},
		{Principal: carol, Resource: patientDB, Action: governance.Action{Verb: "read"}, Environment: "production", MFAVerified: true},
		{Principal: dave, Resource: publicDocs, Action: governance.Action{Verb: "read"}, Environment: "dev", MFAVerified: false},
		{Principal: bob, Resource: patientDB, Action: governance.Action{Verb: "read"}, Environment: "staging", MFAVerified: false},
		{Principal: bob, Resource: patientDB, Action: governance.Action{Verb: "read"}, Environment: "staging", MFAVerified: true},
	}

	for _, ctx := range scenarios {
		result := engine.Evaluate(ctx)
		printDecision(ctx, result.Decision)
	}

	// Compliance Checks.
	separator("COMPLIANCE CHECKS")

	checker := governance.DefaultComplianceChecker()

	rogueDB := governance.Resource{
		ID:             "db-legacy-public",
		Type:           "database",
		Classification: "public",
		Tags:           map[string]string{},
	}

	for _, res := range []governance.Resource{patientDB, publicDocs, rogueDB} {
		report := checker.Evaluate(res)
		fmt.Printf("\n  Resource : %s\n", report.ResourceID)
		if report.Compliant() {
			fmt.Println("  Status   : Compliant")
		} else {
			fmt.Printf("  Status   : Non-Compliant (%d violation(s))\n", len(report.Violations))
			for _, v := range report.Violations {
				fmt.Printf("             -> %s\n", v)
			}
		}
	}

	// Evaluation Trace.
	separator("EVALUATION TRACE")

	{
		ctx := governance.RequestContext{
			Principal:   bob,
			Resource:    prodAPI,
			Action:      governance.Action{Verb: "write"},
			Environment: "production",
			MFAVerified: false,
		}
		result := engine.Evaluate(ctx)
		fmt.Printf("\n  Principal : %s [%s]\n", ctx.Principal.ID, ctx.Principal.Role)
		fmt.Printf("  Resource  : %s\n", ctx.Resource.ID)
		fmt.Printf("  Action    : %s @ %s\n", ctx.Action.Verb, ctx.Environment)
		fmt.Printf("  Decision  : %s <- %s\n", effectStr(result.Decision.Effect), result.Decision.PolicyName)
		printTrace(result.Trace)
	}

	// JSON Output.
	separator("JSON OUTPUT")

	{
		ctx := governance.RequestContext{
			Principal:   alice,
			Resource:    patientDB,
			Action:      governance.Action{Verb: "read"},
			Environment: "production",
			MFAVerified: true,
		}
		result := engine.Evaluate(ctx)
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Printf("\n  EvaluationResult:\n%s\n", string(data))
	}

	{
		report := checker.Evaluate(rogueDB)
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Printf("\n  ComplianceReport:\n%s\n", string(data))
	}

	bar := strings.Repeat("-", 55)
	fmt.Printf("\n%s\n  Governance evaluation complete.\n%s\n\n", bar, bar)
}
