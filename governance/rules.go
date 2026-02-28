package governance

// DefaultComplianceChecker returns a ComplianceChecker pre-loaded with
// standard governance rules.
func DefaultComplianceChecker() *ComplianceChecker {
	checker := &ComplianceChecker{}

	checker.AddRule(ComplianceRule{
		Name:        "RequiresOwnerTag",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Resource must have an 'owner' tag.",
		Check: func(r Resource) bool {
			_, ok := r.Tags["owner"]
			return ok
		},
	})

	checker.AddRule(ComplianceRule{
		Name:        "SecretsNotPublic",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Resources of type 'secret' must not be classified as 'public'.",
		Check: func(r Resource) bool {
			return !(r.Type == "secret" && r.Classification == "public")
		},
	})

	checker.AddRule(ComplianceRule{
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
	})

	checker.AddRule(ComplianceRule{
		Name:        "NoUnclassifiedResources",
		Version:     "1.0",
		Author:      "governance-team",
		Description: "Every resource must have a non-empty classification.",
		Check: func(r Resource) bool {
			return r.Classification != ""
		},
	})

	return checker
}
