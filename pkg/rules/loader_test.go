// ANCHOR: Unit tests for rule loading functionality - Phase 3.4 Week 3
// Tests file-based YAML loading with validation and error handling

package rules

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadRulesFromFile tests loading rules from YAML file
func TestLoadRulesFromFile(t *testing.T) {
	tests := []struct {
		name          string
		filePath      string
		setupFile     func(t *testing.T, path string) // Setup function to create test file
		shouldFail    bool
		expectedCount int
		expectedError string
	}{
		{
			name:       "Load valid rules from file",
			shouldFail: false,
			setupFile: func(t *testing.T, path string) {
				content := `---
- controlID: TEST_1.0.0
  title: Test Control 1
  severity: HIGH
  eventTypes:
    - process_execution
  conditions:
    - field: process.uid
      operator: equals
      value: 0
- controlID: TEST_2.0.0
  title: Test Control 2
  severity: MEDIUM
  eventTypes:
    - pod_spec_check
  conditions:
    - field: container.privileged
      operator: equals
      value: true
`
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			},
			expectedCount: 2,
		},
		{
			name:          "Empty file path",
			filePath:      "",
			shouldFail:    true,
			expectedError: "file path cannot be empty",
		},
		{
			name:          "Non-existent file",
			filePath:      "/tmp/non-existent-rules-file-12345.yaml",
			shouldFail:    true,
			expectedError: "failed to read rules file",
		},
		{
			name:       "Invalid YAML syntax",
			shouldFail: true,
			setupFile: func(t *testing.T, path string) {
				content := `---
- controlID: TEST_1.0.0
  title: Test Control
  severity: HIGH
  eventTypes: [
    - process_execution  # Invalid YAML - mixing styles
`
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			},
			expectedError: "failed to parse YAML",
		},
		{
			name:       "Empty YAML file",
			shouldFail: true,
			setupFile: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("---\n"), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			},
			expectedError: "no rules found in file",
		},
		{
			name:       "Missing controlID",
			shouldFail: true,
			setupFile: func(t *testing.T, path string) {
				content := `---
- title: Test Control
  severity: HIGH
  eventTypes:
    - process_execution
  conditions:
    - field: process.uid
      operator: equals
      value: 0
`
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			},
			expectedError: "missing controlID",
		},
		{
			name:       "Missing title",
			shouldFail: true,
			setupFile: func(t *testing.T, path string) {
				content := `---
- controlID: TEST_1.0.0
  severity: HIGH
  eventTypes:
    - process_execution
  conditions:
    - field: process.uid
      operator: equals
      value: 0
`
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			},
			expectedError: "missing title",
		},
		{
			name:       "Missing severity",
			shouldFail: true,
			setupFile: func(t *testing.T, path string) {
				content := `---
- controlID: TEST_1.0.0
  title: Test Control
  eventTypes:
    - process_execution
  conditions:
    - field: process.uid
      operator: equals
      value: 0
`
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			},
			expectedError: "missing severity",
		},
		{
			name:       "Missing eventTypes",
			shouldFail: true,
			setupFile: func(t *testing.T, path string) {
				content := `---
- controlID: TEST_1.0.0
  title: Test Control
  severity: HIGH
  conditions:
    - field: process.uid
      operator: equals
      value: 0
`
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			},
			expectedError: "missing eventTypes",
		},
		{
			name:       "Missing conditions",
			shouldFail: true,
			setupFile: func(t *testing.T, path string) {
				content := `---
- controlID: TEST_1.0.0
  title: Test Control
  severity: HIGH
  eventTypes:
    - process_execution
`
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			},
			expectedError: "missing conditions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file for testing
			tmpFile, err := os.CreateTemp("", "rules-*.yaml")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			tmpFile.Close()

			filePath := tt.filePath
			if tt.setupFile != nil {
				filePath = tmpFile.Name()
				tt.setupFile(t, filePath)
			}

			// Call LoadRulesFromFile
			rules, err := LoadRulesFromFile(filePath)

			// Check error condition
			if tt.shouldFail {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tt.expectedError != "" && !containsSubstring(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
				}
				return
			}

			// Check success condition
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(rules) != tt.expectedCount {
				t.Errorf("expected %d rules, got %d", tt.expectedCount, len(rules))
			}

			// Verify rules are properly typed
			for i, rule := range rules {
				if rule == nil {
					t.Errorf("rule %d is nil", i)
				}
				if rule.ControlID == "" {
					t.Errorf("rule %d has empty ControlID", i)
				}
				if rule.Title == "" {
					t.Errorf("rule %d has empty Title", i)
				}
			}
		})
	}
}

// TestLoadRulesFromFileWithRelativePath tests loading with relative paths
func TestLoadRulesFromFileWithRelativePath(t *testing.T) {
	// Create test file in current directory
	content := `---
- controlID: TEST_RELATIVE.1
  title: Relative Path Test
  severity: LOW
  eventTypes:
    - pod_spec_check
  conditions:
    - field: container.name
      operator: equals
      value: test
`

	tmpDir, err := os.MkdirTemp("", "rules-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulesFile := filepath.Join(tmpDir, "rules.yaml")
	if err := os.WriteFile(rulesFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Change to temp directory
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	defer os.Chdir(oldCwd)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}

	// Load rules with relative path
	rules, err := LoadRulesFromFile("./rules.yaml")
	if err != nil {
		t.Errorf("failed to load rules with relative path: %v", err)
	}

	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
}

// TestConvertYAMLToRule tests conversion of YAML rules to Rule structs
func TestConvertYAMLToRule(t *testing.T) {
	tests := []struct {
		name          string
		ruleYAML      *RuleYAML
		shouldFail    bool
		expectedError string
	}{
		{
			name: "Valid rule with single condition",
			ruleYAML: &RuleYAML{
				ControlID:  "TEST_1.0.0",
				Title:      "Test Control",
				Severity:   "HIGH",
				EventTypes: []string{"process_execution"},
				Conditions: []ConditionYAML{
					{
						Field:    "process.uid",
						Operator: "equals",
						Value:    0,
					},
				},
			},
			shouldFail: false,
		},
		{
			name: "Valid rule with multiple conditions",
			ruleYAML: &RuleYAML{
				ControlID:  "TEST_2.0.0",
				Title:      "Test Control 2",
				Severity:   "MEDIUM",
				EventTypes: []string{"pod_spec_check", "container_check"},
				Conditions: []ConditionYAML{
					{
						Field:    "container.privileged",
						Operator: "equals",
						Value:    true,
					},
					{
						Field:    "container.name",
						Operator: "contains",
						Value:    "admin",
					},
				},
			},
			shouldFail: false,
		},
		{
			name: "Rule with list value in condition",
			ruleYAML: &RuleYAML{
				ControlID:  "TEST_3.0.0",
				Title:      "Capability Check",
				Severity:   "HIGH",
				EventTypes: []string{"capability_usage"},
				Conditions: []ConditionYAML{
					{
						Field:    "capability.name",
						Operator: "in",
						Value:    []string{"NET_ADMIN", "SYS_ADMIN"},
					},
				},
			},
			shouldFail: false,
		},
		{
			name:          "Missing controlID",
			ruleYAML:      &RuleYAML{},
			shouldFail:    true,
			expectedError: "missing controlID",
		},
		{
			name: "Missing title",
			ruleYAML: &RuleYAML{
				ControlID: "TEST_4.0.0",
			},
			shouldFail:    true,
			expectedError: "missing title",
		},
		{
			name: "Missing conditions",
			ruleYAML: &RuleYAML{
				ControlID:  "TEST_5.0.0",
				Title:      "Test",
				Severity:   "HIGH",
				EventTypes: []string{"test"},
			},
			shouldFail:    true,
			expectedError: "missing conditions",
		},
		{
			name: "Missing condition field",
			ruleYAML: &RuleYAML{
				ControlID:  "TEST_6.0.0",
				Title:      "Test",
				Severity:   "HIGH",
				EventTypes: []string{"test"},
				Conditions: []ConditionYAML{
					{
						Operator: "equals",
						Value:    true,
					},
				},
			},
			shouldFail:    true,
			expectedError: "missing field",
		},
		{
			name: "Missing condition operator",
			ruleYAML: &RuleYAML{
				ControlID:  "TEST_7.0.0",
				Title:      "Test",
				Severity:   "HIGH",
				EventTypes: []string{"test"},
				Conditions: []ConditionYAML{
					{
						Field: "test.field",
						Value: true,
					},
				},
			},
			shouldFail:    true,
			expectedError: "missing operator",
		},
		{
			name: "Missing condition value",
			ruleYAML: &RuleYAML{
				ControlID:  "TEST_8.0.0",
				Title:      "Test",
				Severity:   "HIGH",
				EventTypes: []string{"test"},
				Conditions: []ConditionYAML{
					{
						Field:    "test.field",
						Operator: "equals",
						Value:    nil,
					},
				},
			},
			shouldFail:    true,
			expectedError: "missing value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := convertYAMLToRule(tt.ruleYAML)

			if tt.shouldFail {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tt.expectedError != "" && !containsSubstring(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if rule == nil {
				t.Errorf("rule is nil")
				return
			}

			if rule.ControlID != tt.ruleYAML.ControlID {
				t.Errorf("expected ControlID %q, got %q", tt.ruleYAML.ControlID, rule.ControlID)
			}

			if rule.Title != tt.ruleYAML.Title {
				t.Errorf("expected Title %q, got %q", tt.ruleYAML.Title, rule.Title)
			}

			if len(rule.Conditions) != len(tt.ruleYAML.Conditions) {
				t.Errorf("expected %d conditions, got %d", len(tt.ruleYAML.Conditions), len(rule.Conditions))
			}
		})
	}
}

// Helper function to check if string contains substring (avoiding conflict with contains() in engine.go)
func containsSubstring(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
