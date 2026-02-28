package governance

// RuleSet groups ComplianceRules under a named bundle.
// Use ComplianceChecker.AddRuleSet to register a RuleSet; rule names will be
// prefixed as "BundleName/RuleName" in violation messages.
type RuleSet struct {
	Name  string
	Rules []ComplianceRule
}

// SOC2RuleSet returns a RuleSet bundling SOC 2 ownership and classification rules.
func SOC2RuleSet() RuleSet {
	return RuleSet{
		Name: "SOC2",
		Rules: []ComplianceRule{
			{
				Name:        "RequiresOwnerTag",
				Version:     "1.0",
				Author:      "governance-team",
				Description: "Resource must have an 'owner' tag.",
				Check: func(r Resource) bool {
					_, ok := r.Tags["owner"]
					return ok
				},
			},
			{
				Name:        "NoUnclassifiedResources",
				Version:     "1.0",
				Author:      "governance-team",
				Description: "Every resource must have a non-empty classification.",
				Check: func(r Resource) bool {
					return r.Classification != ""
				},
			},
		},
	}
}

// DataSecurityRuleSet returns a RuleSet bundling data security protection rules.
func DataSecurityRuleSet() RuleSet {
	return RuleSet{
		Name: "DataSecurity",
		Rules: []ComplianceRule{
			{
				Name:        "SecretsNotPublic",
				Version:     "1.0",
				Author:      "governance-team",
				Description: "Resources of type 'secret' must not be classified as 'public'.",
				Check: func(r Resource) bool {
					return !(r.Type == "secret" && r.Classification == "public")
				},
			},
			{
				Name:        "DatabasesMustBeRestricted",
				Version:     "1.0",
				Author:      "governance-team",
				Description: "Database resources must be classified as 'restricted' or 'confidential'.",
				Check: func(r Resource) bool {
					if r.Type != "database" {
						return true
					}
					return r.Classification == "restricted" || r.Classification == "confidential"
				},
			},
		},
	}
}
