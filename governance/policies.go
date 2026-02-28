package governance

// AdminFullAccess grants unrestricted access to all principals with the admin role.
func AdminFullAccess() Policy {
	return Policy{
		Name:        "AdminFullAccess",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Grants unrestricted access to all principals with the admin role.",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			if ctx.Principal.Role == "admin" {
				return &PolicyDecision{
					Effect:     EffectAllow,
					PolicyName: "AdminFullAccess",
					Reason:     "Admin role has unrestricted access.",
				}
			}
			return nil
		},
	}
}

// MFARequiredForRestricted denies access to restricted resources when MFA has not been verified.
func MFARequiredForRestricted() Policy {
	return Policy{
		Name:        "MFARequiredForRestricted",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Denies access to restricted resources when MFA has not been verified.",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			if ctx.Resource.Classification == "restricted" && !ctx.MFAVerified {
				return &PolicyDecision{
					Effect:     EffectDeny,
					PolicyName: "MFARequiredForRestricted",
					Reason:     "MFA required to access restricted resources.",
				}
			}
			return nil
		},
	}
}

// ProductionImmutability prevents non-admin principals from writing or deleting in production.
func ProductionImmutability() Policy {
	return Policy{
		Name:        "ProductionImmutability",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Prevents non-admin principals from writing or deleting in production.",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			if ctx.Environment == "production" &&
				ctx.Principal.Role != "admin" &&
				(ctx.Action.Verb == "write" || ctx.Action.Verb == "delete") {
				return &PolicyDecision{
					Effect:     EffectDeny,
					PolicyName: "ProductionImmutability",
					Reason:     "Write/delete operations require admin role in production.",
				}
			}
			return nil
		},
	}
}

// AnalystReadOnly restricts analysts to read-only access on non-sensitive resources.
func AnalystReadOnly() Policy {
	return Policy{
		Name:        "AnalystReadOnly",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Restricts analysts to read-only access on non-sensitive resources.",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			if ctx.Principal.Role != "analyst" {
				return nil
			}
			if ctx.Action.Verb != "read" {
				return &PolicyDecision{
					Effect:     EffectDeny,
					PolicyName: "AnalystReadOnly",
					Reason:     "Analysts are limited to read-only access.",
				}
			}
			if ctx.Resource.Classification == "restricted" ||
				ctx.Resource.Classification == "confidential" {
				return &PolicyDecision{
					Effect:     EffectDeny,
					PolicyName: "AnalystReadOnly",
					Reason:     "Analysts cannot access confidential or restricted data.",
				}
			}
			return &PolicyDecision{
				Effect:     EffectAllow,
				PolicyName: "AnalystReadOnly",
				Reason:     "Analyst read access on non-sensitive resource allowed.",
			}
		},
	}
}

// EngineerAccess grants engineers full access in dev/staging and read-only in production.
func EngineerAccess() Policy {
	return Policy{
		Name:        "EngineerAccess",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Grants engineers full access in dev/staging and read-only in production.",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			if ctx.Principal.Role != "engineer" {
				return nil
			}
			// Defer restricted resources to other policies (e.g. MFA check).
			if ctx.Resource.Classification == "restricted" {
				return nil
			}
			if ctx.Environment == "dev" || ctx.Environment == "staging" {
				return &PolicyDecision{
					Effect:     EffectAllow,
					PolicyName: "EngineerAccess",
					Reason:     "Engineers have full access in non-production environments.",
				}
			}
			if ctx.Environment == "production" && ctx.Action.Verb == "read" {
				return &PolicyDecision{
					Effect:     EffectAllow,
					PolicyName: "EngineerAccess",
					Reason:     "Engineers can read production resources.",
				}
			}
			return nil
		},
	}
}

// DefaultPolicyEngine returns a PolicyEngine pre-loaded with all built-in
// policies in recommended evaluation order.
func DefaultPolicyEngine() *PolicyEngine {
	engine := &PolicyEngine{}
	engine.RegisterPolicy(AdminFullAccess())
	engine.RegisterPolicy(MFARequiredForRestricted())
	engine.RegisterPolicy(ProductionImmutability())
	engine.RegisterPolicy(AnalystReadOnly())
	engine.RegisterPolicy(EngineerAccess())
	return engine
}
