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
