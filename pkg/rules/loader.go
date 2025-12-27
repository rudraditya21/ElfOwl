// ANCHOR: CIS rule loading from file and ConfigMap - Phase 3.1 Week 3
// Loads rule definitions from YAML files or Kubernetes ConfigMap
// Supports flexible rule source configuration with fallback to hardcoded rules

package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
// Parses YAML content from ConfigMap data field using standard K8s clientset
// Supports configurable data key (e.g., "rules.yaml", "cis-controls.yaml", etc.)
func LoadRulesFromConfigMap(ctx context.Context, clientset *kubernetes.Clientset, configMapName, configMapNamespace, dataKey string) ([]*Rule, error) {
	if configMapName == "" {
		return nil, fmt.Errorf("ConfigMap name cannot be empty")
	}
	if configMapNamespace == "" {
		return nil, fmt.Errorf("ConfigMap namespace cannot be empty")
	}
	if dataKey == "" {
		return nil, fmt.Errorf("ConfigMap data key cannot be empty")
	}

	if clientset == nil {
		return nil, fmt.Errorf("clientset cannot be nil")
	}

	// Query K8s API for ConfigMap
	configMap, err := clientset.CoreV1().ConfigMaps(configMapNamespace).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s/%s: %w", configMapNamespace, configMapName, err)
	}

	// Extract YAML content from ConfigMap data using specified key
	yamlContent, exists := configMap.Data[dataKey]
	if !exists {
		return nil, fmt.Errorf("ConfigMap %s/%s does not contain '%s' key", configMapNamespace, configMapName, dataKey)
	}

	if yamlContent == "" {
		return nil, fmt.Errorf("rules.yaml in ConfigMap %s/%s is empty", configMapNamespace, configMapName)
	}

	// Parse YAML content
	var rulesYAML []RuleYAML
	if err := yaml.Unmarshal([]byte(yamlContent), &rulesYAML); err != nil {
		return nil, fmt.Errorf("failed to parse YAML from ConfigMap %s/%s: %w", configMapNamespace, configMapName, err)
	}

	if len(rulesYAML) == 0 {
		return nil, fmt.Errorf("no rules found in ConfigMap %s/%s", configMapNamespace, configMapName)
	}

	// Convert YAML rules to Rule structs
	rules := make([]*Rule, 0, len(rulesYAML))
	for i, ruleYAML := range rulesYAML {
		rule, err := convertYAMLToRule(&ruleYAML)
		if err != nil {
			return nil, fmt.Errorf("failed to convert rule %d (%s) from ConfigMap %s/%s: %w", i+1, ruleYAML.ControlID, configMapNamespace, configMapName, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}
