# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
go test ./...

# Run tests with verbose output (shows individual test names)
go test -v ./governance/

# Run a single test function
go test -v ./governance/ -run TestAdminFullAccess

# Run the demo application
go run ./cmd/demo/

# Build the demo binary
go build -o governance_demo ./cmd/demo/
```

## Architecture

This is a Go library (zero external dependencies) implementing two distinct policy primitives: access control and compliance checking.

### Two Independent Subsystems

**PolicyEngine** (`policy_engine.go`) — access control with short-circuit evaluation:
- Policies are registered in order; registration order determines evaluation priority
- Deny-wins, fail-closed: first `Deny` short-circuits; first `Allow` wins only if no `Deny` appears; default deny if all policies abstain
- A policy returns `nil` to abstain (`*PolicyDecision` nil = "no opinion"), non-nil to decide
- Every `Evaluate()` call returns `EvaluationResult{Decision, Trace}` — the trace captures every policy consulted (including the short-circuit point)

**ComplianceChecker** (`compliance.go`) — audit-style, intentionally non-short-circuiting:
- Evaluates every registered rule regardless of prior failures
- Accumulates all violations into `ComplianceReport{ResourceID, Violations[]string}`
- `report.Compliant()` is a value receiver (not pointer) — important since `checker.Evaluate()` returns a value, not a pointer

### Type Relationships

```
RequestContext → PolicyEngine.Evaluate() → EvaluationResult
                                           ├── PolicyDecision{Effect, PolicyName, Reason}
                                           └── EvaluationTrace{Context, Steps[]}

Resource → ComplianceChecker.Evaluate() → ComplianceReport{ResourceID, Violations[]}
```

`Effect` and `StepOutcome` are `int` types with custom `MarshalJSON()` — they serialize as strings (`"Allow"`, `"Deny"`, `"Abstain"`), not integers.

### JSON Shape

`EvaluationResult.MarshalJSON()` in `json.go` flattens the trace context — the JSON output puts `principal`, `resource`, `action`, `environment` directly inside the `trace` object (not nested under `context`). This matches the C++ original's output shape.

`ComplianceReport.MarshalJSON()` adds a computed `"compliant"` boolean field that is not present on the struct itself.

### Built-in Defaults

`DefaultPolicyEngine()` registers 5 policies in priority order:
1. `AdminFullAccess` — admin role always allows
2. `MFARequiredForRestricted` — restricted resource + no MFA → deny
3. `ProductionImmutability` — non-admin write/delete in production → deny
4. `AnalystReadOnly` — analyst role: deny writes and confidential/restricted reads
5. `EngineerAccess` — engineer: allow all in dev/staging, read-only in production

`DefaultComplianceChecker()` registers 4 rules: `RequiresOwnerTag`, `SecretsNotPublic`, `DatabasesMustBeRestricted`, `NoUnclassifiedResources`.

### Test Structure

Tests are in `governance/` as an external test package (`package governance_test`). Table-driven subtests use `t.Run`. Helper functions `makeDefaultEngine()` and `makeResource()` avoid repetition. 11 tests in `policy_engine_test.go`, 9 in `compliance_test.go`.

### Releases

Tagged releases (`v*`) trigger `.github/workflows/release.yml`, which builds cross-platform binaries (Linux/macOS/Windows, amd64/arm64) and publishes a GitHub Release with SHA256 checksums.
