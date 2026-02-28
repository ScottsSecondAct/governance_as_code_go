package governance

import "strings"

// policyNames extracts the Name fields from a slice of policies.
func policyNames(policies []Policy) []string {
	names := make([]string, len(policies))
	for i, p := range policies {
		names[i] = p.Name
	}
	return names
}

// AllOf returns a Policy that allows only when all sub-policies allow.
//
// Semantics:
//   - First Deny short-circuits with a Deny decision.
//   - If any sub-policy abstains (and no Deny occurred), the combinator abstains.
//   - All Allow → Allow.
//   - Zero sub-policies → Allow (vacuous truth).
func AllOf(name string, policies ...Policy) Policy {
	names := policyNames(policies)
	return Policy{
		Name:        name,
		Version:     "1.0",
		Author:      "governance-team",
		Description: "AllOf combinator over [" + strings.Join(names, ", ") + "]",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			if len(policies) == 0 {
				return &PolicyDecision{
					Effect:     EffectAllow,
					PolicyName: name,
					Reason:     "AllOf with zero sub-policies (vacuous truth).",
				}
			}
			hasAbstain := false
			for _, p := range policies {
				d := p.Evaluate(ctx)
				if d == nil {
					hasAbstain = true
					continue
				}
				if d.Effect == EffectDeny {
					return &PolicyDecision{
						Effect:     EffectDeny,
						PolicyName: name,
						Reason:     "AllOf denied by sub-policy " + p.Name + ": " + d.Reason,
					}
				}
			}
			if hasAbstain {
				return nil
			}
			return &PolicyDecision{
				Effect:     EffectAllow,
				PolicyName: name,
				Reason:     "AllOf: all sub-policies allowed.",
			}
		},
	}
}

// AnyOf returns a Policy that allows on the first Allow.
// If no sub-policy allows and at least one denies, it denies (using the first deny encountered).
// If all sub-policies abstain, it abstains.
func AnyOf(name string, policies ...Policy) Policy {
	names := policyNames(policies)
	return Policy{
		Name:        name,
		Version:     "1.0",
		Author:      "governance-team",
		Description: "AnyOf combinator over [" + strings.Join(names, ", ") + "]",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			var firstDeny *PolicyDecision
			var firstDenyName string
			for _, p := range policies {
				d := p.Evaluate(ctx)
				if d == nil {
					continue
				}
				if d.Effect == EffectAllow {
					return &PolicyDecision{
						Effect:     EffectAllow,
						PolicyName: name,
						Reason:     "AnyOf allowed by sub-policy " + p.Name + ": " + d.Reason,
					}
				}
				if firstDeny == nil {
					firstDeny = d
					firstDenyName = p.Name
				}
			}
			if firstDeny != nil {
				return &PolicyDecision{
					Effect:     EffectDeny,
					PolicyName: name,
					Reason:     "AnyOf denied by sub-policy " + firstDenyName + ": " + firstDeny.Reason,
				}
			}
			return nil
		},
	}
}

// NoneOf returns a Policy that denies when any sub-policy allows (block-list semantics).
// Abstains otherwise (including when all sub-policies abstain or all deny).
func NoneOf(name string, policies ...Policy) Policy {
	names := policyNames(policies)
	return Policy{
		Name:        name,
		Version:     "1.0",
		Author:      "governance-team",
		Description: "NoneOf combinator over [" + strings.Join(names, ", ") + "]",
		Evaluate: func(ctx RequestContext) *PolicyDecision {
			for _, p := range policies {
				d := p.Evaluate(ctx)
				if d != nil && d.Effect == EffectAllow {
					return &PolicyDecision{
						Effect:     EffectDeny,
						PolicyName: name,
						Reason:     "NoneOf blocked by sub-policy " + p.Name + ": " + d.Reason,
					}
				}
			}
			return nil
		},
	}
}
