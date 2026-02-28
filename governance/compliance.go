package governance

import "fmt"

// ComplianceRule is a named compliance check applied to a Resource.
type ComplianceRule struct {
	Name        string
	Version     string
	Author      string
	Description string
	Check       func(Resource) bool
}

// ComplianceChecker evaluates resources against a set of named rules.
type ComplianceChecker struct {
	rules []ComplianceRule
}

// AddRule appends a rule to the checker's evaluation list.
func (c *ComplianceChecker) AddRule(rule ComplianceRule) {
	c.rules = append(c.rules, rule)
}

// AddRules appends multiple rules to the checker's evaluation list.
func (c *ComplianceChecker) AddRules(rules []ComplianceRule) {
	for _, rule := range rules {
		c.rules = append(c.rules, rule)
	}
}

// AddRuleSet appends all rules from a RuleSet, prefixing each rule's Name with
// "BundleName/RuleName" so violations read "[BundleName/RuleName] ...".
// The original RuleSet is not modified.
func (c *ComplianceChecker) AddRuleSet(rs RuleSet) {
	for _, rule := range rs.Rules {
		prefixed := ComplianceRule{
			Name:        rs.Name + "/" + rule.Name,
			Version:     rule.Version,
			Author:      rule.Author,
			Description: rule.Description,
			Check:       rule.Check,
		}
		c.rules = append(c.rules, prefixed)
	}
}

// RuleCount returns the number of registered rules.
func (c *ComplianceChecker) RuleCount() int {
	return len(c.rules)
}

// Evaluate runs all rules against resource and returns a ComplianceReport.
func (c *ComplianceChecker) Evaluate(resource Resource) ComplianceReport {
	report := ComplianceReport{
		ResourceID: resource.ID,
		Violations: []string{},
	}
	for _, rule := range c.rules {
		if !rule.Check(resource) {
			report.Violations = append(report.Violations,
				fmt.Sprintf("[%s] %s", rule.Name, rule.Description))
		}
	}
	return report
}
