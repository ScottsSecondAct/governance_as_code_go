# Governance as Code — Go
![AI Assisted](https://img.shields.io/badge/AI%20Assisted-Claude-blue?logo=anthropic)

A self-contained Go library demonstrating **policy enforcement** and **compliance checking** as first-class code constructs — with structured audit trails, JSON serialization for SIEM integration, and zero external dependencies.

This is a Go port of [governance_as_code](https://github.com/ScottsSecondAct/governance_as_code) (C++17). It preserves all semantics, types, and test coverage of the original while adopting Go idioms: pointer-returning policy functions instead of `std::optional`, table-driven subtests with `t.Run`, and `encoding/json` with `MarshalJSON` methods instead of hand-rolled serialization.

## Why Go

The cloud-native policy and governance ecosystem — OPA, Kubernetes admission controllers, Terraform providers, Open Policy Agent — is built in Go. Porting this project to Go makes the same concepts a natural fit for that environment: the types translate directly, the semantics are identical, and the library can be imported by any Go toolchain without a C++ build step.

## The Policy Model

A `Policy` is a named function from a `RequestContext` to a `*PolicyDecision`. Returning `nil` means the policy **abstains** — it has no opinion on this request. Returning a non-nil pointer produces a decision with a policy name and human-readable reason.

```go
func RequireMFAForConfidential() governance.Policy {
    return governance.Policy{
        Name:        "RequireMFAForConfidential",
        Version:     "1.0",
        Author:      "security-team",
        Description: "Deny access to confidential resources when MFA has not been verified.",
        Evaluate: func(ctx governance.RequestContext) *governance.PolicyDecision {
            if ctx.Resource.Classification == "confidential" && !ctx.MFAVerified {
                return &governance.PolicyDecision{
                    Effect:     governance.EffectDeny,
                    PolicyName: "RequireMFAForConfidential",
                    Reason:     "MFA required for confidential resources.",
                }
            }
            return nil // abstain: not my concern, let other policies decide
        },
    }
}

engine.RegisterPolicy(RequireMFAForConfidential())
```

### Resolution Strategy (Fail-Closed)

The engine uses a **deny-wins, fail-closed** strategy:

1. **First `Deny` wins** — evaluation stops immediately; remaining policies are not consulted.
2. **First `Allow` sticks** — if no `Deny` appears after all policies are checked, the first `Allow` is returned.
3. **Default: `Deny`** — if no policy produces a decision, access is denied. Abstaining is never silently promoted to access.

```go
engine := governance.DefaultPolicyEngine()

ctx := governance.RequestContext{
    Principal:   governance.Principal{ID: "bob@corp.io", Role: "engineer", Department: "Backend"},
    Resource:    governance.Resource{ID: "prod-db", Type: "database", Classification: "restricted"},
    Action:      governance.Action{Verb: "write"},
    Environment: "production",
    MFAVerified: false,
}

result := engine.Evaluate(ctx)
// result.Decision.Effect     == governance.EffectDeny
// result.Decision.PolicyName == "MFARequiredForRestricted"
// result.Decision.Reason     == "MFA required to access restricted resources."
```

### Evaluation Traces

Every call to `Evaluate()` returns an `EvaluationResult` containing the final decision and a full `EvaluationTrace` — a complete, ordered record of every policy consulted during that evaluation:

```go
result := engine.Evaluate(ctx)

for _, step := range result.Trace.Steps {
    // step.PolicyName — which policy was evaluated
    // step.Outcome    — StepAllow, StepDeny, or StepAbstain
    // step.Reason     — human-readable explanation (empty on Abstain)
}

fmt.Println("Evaluated:", result.Trace.EvaluatedCount())
fmt.Println("Abstained:", result.Trace.AbstainCount())
```

Trace for an engineer attempting a write in production:

```
[Abstain] AdminFullAccess
[Abstain] MFARequiredForRestricted
[Deny   ] ProductionImmutability -- Write/delete operations require admin role in production.
```

The Deny short-circuits evaluation. Policies registered after `ProductionImmutability` never appear in the trace.

## Architecture

```
  RequestContext
  (Principal, Resource, Action,
   Environment, MFAVerified)
        │
        ▼
 ┌─────────────────┐   Iterates registered policies in order. Records
 │  PolicyEngine   │   each step (Allow / Deny / Abstain) into the
 │  Evaluate()     │   trace. Short-circuits and returns on first Deny.
 │                 │   Default deny if no policy grants access.
 └────────┬────────┘
          │ EvaluationResult
          ├── PolicyDecision   (Effect, PolicyName, Reason)
          └── EvaluationTrace
                  ├── Context   (RequestContext snapshot)
                  └── Steps[]   (PolicyStep per policy consulted)

  Resource
  (ID, Type, Classification, Tags)
        │
        ▼
 ┌─────────────────┐   Evaluates every registered rule regardless of
 │ ComplianceCheck-│   prior results — all violations are captured,
 │ er Evaluate()   │   not just the first. Non-short-circuiting by
 │                 │   design: audits want the full picture.
 └────────┬────────┘
          │ ComplianceReport
          ├── ResourceID
          ├── Compliant()
          └── Violations[]   (one entry per failed rule)

  EvaluationResult / ComplianceReport
        │
        ▼
 ┌─────────────────┐   MarshalJSON methods on Effect, StepOutcome,
 │ encoding/json   │   EvaluationResult, and ComplianceReport.
 │ MarshalJSON()   │   EvaluationResult flattens trace context into
 └─────────────────┘   principal/resource/action/environment keys.
          │ []byte (valid JSON)
          ▼
    SIEM / log pipeline
```

## Technical Highlights

### Type Design

The core types in `governance/types.go` are plain structs with no embedding or interface requirements:

| Type | Fields |
|---|---|
| `Principal` | `ID`, `Role`, `Department` |
| `Resource` | `ID`, `Type`, `Classification`, `Tags` (`map[string]string`) |
| `Action` | `Verb` (`"read"`, `"write"`, `"delete"`, `"execute"`) |
| `RequestContext` | `Principal`, `Resource`, `Action`, `Environment`, `MFAVerified` |
| `PolicyDecision` | `Effect` (`EffectAllow`/`EffectDeny`), `PolicyName`, `Reason` |

`PolicyFn` is `func(RequestContext) *PolicyDecision`. The pointer return type encodes the abstain-or-decide distinction directly — `nil` for abstain, non-nil for a concrete decision. This is the Go equivalent of `std::optional<PolicyDecision>` from the C++ original.

### Deny-Wins Evaluation Loop

The evaluation loop in `PolicyEngine.Evaluate()` builds the trace as it iterates:

```go
for _, policy := range e.policies {
    decision := policy.Evaluate(ctx)
    if decision == nil {
        trace.Steps = append(trace.Steps, PolicyStep{PolicyName: policy.Name, Outcome: StepAbstain})
        continue
    }
    if decision.Effect == EffectDeny {
        trace.Steps = append(trace.Steps, PolicyStep{PolicyName: policy.Name, Outcome: StepDeny, Reason: decision.Reason})
        return EvaluationResult{Decision: *decision, Trace: trace} // short-circuit
    }
    trace.Steps = append(trace.Steps, PolicyStep{PolicyName: policy.Name, Outcome: StepAllow, Reason: decision.Reason})
    if firstAllow == nil { firstAllow = decision }
}
```

`EvaluationTrace.Context` stores a copy of the `RequestContext` at evaluation time, decoupling the audit record from the caller's variable lifetime.

### Compliance vs. Access Control Semantics

`ComplianceChecker` is intentionally **non-short-circuiting**. Unlike `PolicyEngine`, it evaluates every rule and accumulates all violations — reflecting the semantics of an audit:

```go
checker := governance.DefaultComplianceChecker()
report  := checker.Evaluate(rogueDB)

// report.Compliant()  → false
// report.Violations   → [
//   "[RequiresOwnerTag] Resource must have an 'owner' tag.",
//   "[DatabasesMustBeRestricted] Database resources must be classified as ..."
// ]
```

### JSON Serialization

`MarshalJSON` methods in `governance/json.go` produce structured output compatible with the C++ original:

```go
data, _ := json.MarshalIndent(result, "", "  ")
```

```json
{
  "decision": {
    "effect": "Allow",
    "policy_name": "AdminFullAccess",
    "reason": "Admin role has unrestricted access."
  },
  "trace": {
    "principal": "alice@corp.io",
    "resource": "db-patient-records",
    "action": "read",
    "environment": "production",
    "steps": [
      { "policy": "AdminFullAccess", "outcome": "Allow", "reason": "Admin role has unrestricted access." },
      { "policy": "MFARequiredForRestricted", "outcome": "Abstain", "reason": "" },
      { "policy": "ProductionImmutability", "outcome": "Abstain", "reason": "" },
      { "policy": "AnalystReadOnly", "outcome": "Abstain", "reason": "" },
      { "policy": "EngineerAccess", "outcome": "Abstain", "reason": "" }
    ]
  }
}
```

`Effect` and `StepOutcome` implement `MarshalJSON()` to serialize as their string names (`"Allow"`, `"Deny"`, `"Abstain"`). `EvaluationResult.MarshalJSON()` flattens the context fields into the trace object. `ComplianceReport.MarshalJSON()` computes the `compliant` boolean at serialization time.

### Policy Metadata

Every `Policy` and `ComplianceRule` carries version, author, and description fields alongside its logic:

```go
type Policy struct {
    Name        string
    Version     string   // "1.0"
    Author      string   // "governance-team"
    Description string
    Evaluate    PolicyFn
}
```

## Built-in Policies

| Policy | Role | Condition | Effect |
|---|---|---|---|
| `AdminFullAccess` | `admin` | always | `Allow` |
| `MFARequiredForRestricted` | any | `restricted` resource + no MFA | `Deny` |
| `ProductionImmutability` | non-admin | `write`/`delete` in production | `Deny` |
| `AnalystReadOnly` | `analyst` | non-read verb, or `confidential`/`restricted` resource | `Deny`/`Allow` |
| `EngineerAccess` | `engineer` | dev/staging (any verb), production (read only) | `Allow` |

Registration order matters. `MFARequiredForRestricted` fires before `AnalystReadOnly` and `EngineerAccess`, so a request to a restricted resource without MFA is denied regardless of role.

## Built-in Compliance Rules

| Rule | Description |
|---|---|
| `RequiresOwnerTag` | Every resource must have an `owner` tag |
| `SecretsNotPublic` | Resources of type `secret` must not be classified `public` |
| `DatabasesMustBeRestricted` | Databases must be `restricted` or `confidential` |
| `NoUnclassifiedResources` | Every resource must have a non-empty classification |

## Quick Start

**Prerequisites:** Go 1.21+

```bash
git clone https://github.com/ScottsSecondAct/governance_as_code_go
cd governance_as_code_go
go run ./cmd/demo/
```

## Running Tests

```bash
go test ./...
go test -v ./governance/
```

Expected:

```
=== RUN   TestAdminFullAccess
--- PASS: TestAdminFullAccess (0.00s)
...
ok  	github.com/ScottsSecondAct/governance_as_code_go/governance
```

20 tests across 2 files covering all policy behaviors, compliance rules, trace semantics, and JSON output.

## File Structure

```
governance_as_code_go/
├── go.mod
├── governance/
│   ├── types.go              # all shared types + JSON struct tags
│   ├── json.go               # MarshalJSON for Effect, StepOutcome, EvaluationResult, ComplianceReport
│   ├── policy_engine.go      # PolicyFn, Policy, PolicyEngine
│   ├── policies.go           # 5 built-in policy constructors + DefaultPolicyEngine
│   ├── compliance.go         # ComplianceRule, ComplianceChecker
│   ├── rules.go              # 4 built-in rule constructors + DefaultComplianceChecker
│   ├── policy_engine_test.go # 11 test functions
│   └── compliance_test.go    # 9 test functions
└── cmd/
    └── demo/
        └── main.go           # 4-section demo
```

## Development Process & AI Collaboration

This project was built with AI assistance (Anthropic's Claude) as a design collaborator:

- **Type translation**: Working through the C++ → Go type mapping, particularly `std::optional<PolicyDecision>` → `*PolicyDecision` (nil = abstain) and `std::function<...>` → `func(RequestContext) *PolicyDecision`.
- **JSON architecture**: Deciding between struct tags alone vs. custom `MarshalJSON` methods — needed custom methods for `Effect`/`StepOutcome` (enum-to-string), `EvaluationResult` (flattened trace shape), and `ComplianceReport` (computed `compliant` field).
- **Receiver semantics**: Catching the non-addressable temporary issue with pointer receivers on `Compliant()` when called on `checker.Evaluate(r).Compliant()` — value receiver is correct here.
- **Test porting**: Designing table-driven subtests with `t.Run` as the Go equivalent of the C++ test suites.

Every design decision was reviewed, understood, and intentional.

## Roadmap

- [x] Deny-wins, fail-closed policy engine
- [x] Compliance checker with exhaustive violation accumulation
- [x] Five built-in policies covering common access control patterns
- [x] Four built-in compliance rules (ownership, classification, database restrictions)
- [x] Structured `EvaluationTrace` with per-step outcomes
- [x] Policy and rule metadata (version, author, description)
- [x] JSON serialization via `encoding/json` with custom marshalers
- [ ] Logical policy combinators (`AllOf`, `AnyOf`, `NoneOf`)
- [ ] Named compliance rule bundles (e.g., `PCI-DSS`, `SOC2`)
- [ ] Runtime policy loading from YAML/JSON configuration files
- [ ] gRPC/HTTP policy evaluation server

## License

MIT
