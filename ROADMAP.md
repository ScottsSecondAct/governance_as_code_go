# Roadmap

This document describes the planned direction for Governance as Code — Go. It is a living document and will evolve as the project matures.

---

## v0.1 — Foundation (released)

The initial release establishes the core primitives as a Go port of the C++17 original:

- **Policy Engine** with deny-wins, fail-closed evaluation
- **Compliance Checker** with per-resource violation reporting
- Five built-in policies covering common access control patterns (admin bypass, MFA enforcement, production immutability, role-based read constraints)
- Four built-in compliance rules (owner tagging, secret classification, database restrictions, no unclassified resources)
- Zero external dependencies (Go standard library only)
- Demo application and test suites

---

## v0.2 — Decision Transparency (released)

Make policy evaluation observable and auditable.

- **Audit trail**: capture every policy evaluation step (policy name, input context, outcome) into a structured `EvaluationTrace`
- **Decision explanation**: return the full ordered list of policy outcomes alongside the final decision, not just the winning one
- **JSON serialization**: `MarshalJSON` methods on `Effect`, `StepOutcome`, `EvaluationResult`, and `ComplianceReport` for integration with logging and SIEM pipelines
- **Policy metadata**: attach version, author, and description fields to `Policy` and `ComplianceRule` structs

---

## v0.3 — Policy Composition

Allow policies to be built from smaller, reusable pieces.

- **Logical combinators**: `AllOf`, `AnyOf`, `NoneOf` wrappers that compose `PolicyFn` functions
- **Conditional policies**: activate a policy only when a predicate on the context is true (e.g., only in production, only for a specific resource type)
- **Named rule sets**: group compliance rules into named bundles (e.g., `PCI-DSS`, `SOC2`) that can be applied or skipped as a unit
- **Policy priority / ordering API**: explicit ordering control beyond registration order

---

## v0.4 — Configuration-Driven Policies

Enable policies and rules to be expressed outside of compiled code.

- **YAML/JSON policy definitions**: load simple attribute-matching policies from configuration files at runtime
- **Environment-aware defaults**: built-in support for environment tiers (dev / staging / prod) as first-class configuration
- **Hot reload**: detect and apply policy file changes without restarting the host process
- **Schema validation**: validate policy config files and emit clear errors on malformed input

---

## v1.0 — Real-World Integration

Move from a demonstration project to a library suitable for embedding in production systems.

- **gRPC authorization server**: optional server implementing the [Envoy external authorization API](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/attribute_context.proto), making the engine usable as a sidecar
- **Open Policy Agent (OPA) bridge**: evaluate Rego policies alongside native Go policies within the same engine
- **Kubernetes admission webhook**: optional server target for use as a validating or mutating admission controller
- **Multi-principal evaluation**: evaluate requests involving delegated or impersonated principals
- **Policy versioning**: tag policies with versions, support running multiple versions concurrently during migration

---

## Future / Under Consideration

Ideas being evaluated for later milestones:

- **Policy linting**: static analysis to detect conflicting or shadowed policies before deployment
- **Web UI**: visual policy explorer showing which policies apply to a given principal/resource/action combination
- **ABAC extensions**: richer attribute expressions beyond the current tag-matching model
- **Prometheus metrics**: expose evaluation latency, decision distribution, and rule hit rates
- **Contribution guide and stable API**: once the architecture is settled, open the project to external contributions

---

## Release History

| Version | Status | Notes |
|---------|--------|-------|
| v0.1.0 | Released | Initial release — Go port of governance_as_code (C++17) |
