// ANCHOR: CIS rule loading from file and ConfigMap - Phase 3.1 Week 3
// Loads rule definitions from YAML files or Kubernetes ConfigMap
// Supports flexible rule source configuration with fallback to hardcoded rules

package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// RuleYAML is the YAML representation of a Rule for file-based configuration
type RuleYAML struct {
	ControlID  string         `yaml:"controlID"`
	Title      string         `yaml:"title"`
	Severity   string         `yaml:"severity"`
	EventTypes []string       `yaml:"eventTypes"`
	Conditions []ConditionYAML `yaml:"conditions"`
}

// ConditionYAML is the YAML representation of a Condition
type ConditionYAML struct {
	Field    string      `yaml:"field"`
	Operator string      `yaml:"operator"`
	Value    interface{} `yaml:"value"`
}

// LoadRulesFromFile loads rules from a YAML file
// ANCHOR: File-based rule loading with path resolution - Phase 3.1 Week 3
// Supports both absolute and relative file paths with proper error handling
// Returns loaded rules converted to Rule struct format suitable for rule engine
func LoadRulesFromFile(filePath string) ([]*Rule, error) {
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Resolve file path (handle relative paths)
	resolvedPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve file path %s: %w", filePath, err)
	}

	// Read YAML file
	fileData, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %w", resolvedPath, err)
	}

	// Parse YAML content
	var rulesYAML []RuleYAML
	if err := yaml.Unmarshal(fileData, &rulesYAML); err != nil {
		return nil, fmt.Errorf("failed to parse YAML from %s: %w", resolvedPath, err)
	}

	if len(rulesYAML) == 0 {
		return nil, fmt.Errorf("no rules found in file %s", resolvedPath)
	}

	// Convert YAML rules to Rule structs
	rules := make([]*Rule, 0, len(rulesYAML))
	for i, ruleYAML := range rulesYAML {
		rule, err := convertYAMLToRule(&ruleYAML)
		if err != nil {
			return nil, fmt.Errorf("failed to convert rule %d (%s): %w", i+1, ruleYAML.ControlID, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// convertYAMLToRule converts a RuleYAML to a Rule struct
// ANCHOR: YAML to Rule struct conversion with validation - Phase 3.1 Week 3
// Ensures all required fields are present and properly formatted
func convertYAMLToRule(ruleYAML *RuleYAML) (*Rule, error) {
	if ruleYAML.ControlID == "" {
		return nil, fmt.Errorf("missing controlID in rule")
	}
	if ruleYAML.Title == "" {
		return nil, fmt.Errorf("missing title in rule %s", ruleYAML.ControlID)
	}
	if ruleYAML.Severity == "" {
		return nil, fmt.Errorf("missing severity in rule %s", ruleYAML.ControlID)
	}
	if len(ruleYAML.EventTypes) == 0 {
		return nil, fmt.Errorf("missing eventTypes in rule %s", ruleYAML.ControlID)
	}
	if len(ruleYAML.Conditions) == 0 {
		return nil, fmt.Errorf("missing conditions in rule %s", ruleYAML.ControlID)
	}

	// Convert conditions
	conditions := make([]Condition, 0, len(ruleYAML.Conditions))
	for j, condYAML := range ruleYAML.Conditions {
		if condYAML.Field == "" {
			return nil, fmt.Errorf("missing field in condition %d of rule %s", j+1, ruleYAML.ControlID)
		}
		if condYAML.Operator == "" {
			return nil, fmt.Errorf("missing operator in condition %d of rule %s", j+1, ruleYAML.ControlID)
		}
		if condYAML.Value == nil {
			return nil, fmt.Errorf("missing value in condition %d of rule %s", j+1, ruleYAML.ControlID)
		}

		conditions = append(conditions, Condition{
			Field:    condYAML.Field,
			Operator: condYAML.Operator,
			Value:    condYAML.Value,
		})
	}

	return &Rule{
		ControlID:  ruleYAML.ControlID,
		Title:      ruleYAML.Title,
		Severity:   ruleYAML.Severity,
		EventTypes: ruleYAML.EventTypes,
		Conditions: conditions,
	}, nil
}

// LoadRulesFromConfigMap loads rules from a Kubernetes ConfigMap
// ANCHOR: ConfigMap-based rule loading via K8s API - Phase 3.2 Week 3
// Queries K8s API server for ConfigMap in specified namespace
// Parses YAML content from ConfigMap data field
func LoadRulesFromConfigMap(ctx context.Context, configMapName, configMapNamespace string) ([]*Rule, error) {
	// TODO: Phase 3.2 implementation
	// 1. Query K8s API for ConfigMap
	// 2. Parse YAML rule definitions from ConfigMap.Data["rules.yaml"]
	// 3. Return loaded rules

	return nil, fmt.Errorf("not yet implemented")
}
