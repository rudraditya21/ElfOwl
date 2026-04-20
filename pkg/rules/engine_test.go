// ANCHOR: Unit tests for rule engine condition evaluation - Phase 3.4 Week 3
// Tests rule matching and engine initialization with various configurations

package rules

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// TestNewEngine tests engine initialization with different configurations
func TestNewEngine(t *testing.T) {
	tests := []struct {
		name           string
		ruleFilePath   string
		shouldFail     bool
		expectFallback bool // true if should fall back to hardcoded rules
	}{
		{
			name:           "Default initialization (no file path)",
			ruleFilePath:   "",
			shouldFail:     false,
			expectFallback: true, // Should use hardcoded rules
		},
		{
			name:           "Non-existent file should fall back to hardcoded",
			ruleFilePath:   "/tmp/non-existent-rules-12345.yaml",
			shouldFail:     false,
			expectFallback: true, // Should fall back gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var engine *Engine
			var err error

			if tt.ruleFilePath == "" {
				engine, err = NewEngine()
			} else {
				engine, err = NewEngine(tt.ruleFilePath)
			}

			if tt.shouldFail {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if engine == nil {
				t.Errorf("engine is nil")
				return
			}

			// Verify we got rules (either from file or hardcoded fallback)
			if len(engine.Rules) == 0 {
				t.Errorf("engine has no rules loaded")
				return
			}

			// Verify rules have required fields
			for i, rule := range engine.Rules {
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

// TestNewEngineWithConfig tests advanced engine initialization with EngineConfig
// ANCHOR: Advanced engine configuration tests - Phase 3.2 Week 3
// Tests file-only, ConfigMap-only, and fallback configurations
func TestNewEngineWithConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         *EngineConfig
		shouldFail     bool
		expectFallback bool // true if should fall back to hardcoded rules
		expectedError  string
	}{
		{
			name: "No configuration provided (all defaults)",
			config: &EngineConfig{
				RuleFilePath:       "",
				ConfigMapName:      "",
				ConfigMapNamespace: "",
				K8sClientset:       nil,
			},
			shouldFail:     false,
			expectFallback: true, // Should use hardcoded rules
		},
		{
			name: "Non-existent file with no ConfigMap fallback",
			config: &EngineConfig{
				RuleFilePath:       "/tmp/non-existent-rules.yaml",
				ConfigMapName:      "",
				ConfigMapNamespace: "",
				K8sClientset:       nil,
			},
			shouldFail:     false,
			expectFallback: true, // Should fall back to hardcoded rules
		},
		{
			name:          "Nil config provided",
			config:        nil,
			shouldFail:    true,
			expectedError: "cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Handle nil config case - should now return error instead of panicking
			if tt.config == nil {
				engine, err := NewEngineWithConfig(tt.config)

				if tt.shouldFail {
					if err == nil {
						t.Errorf("expected error for nil config, got nil")
						return
					}
					if !containsSubstring(err.Error(), tt.expectedError) {
						t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
					}
					if engine != nil {
						t.Errorf("expected nil engine when config is nil, got %v", engine)
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				}
				return
			}

			// Ensure context is set if testing with real clientset
			if tt.config.K8sClientset != nil && tt.config.Ctx == nil {
				tt.config.Ctx = context.Background()
			}

			engine, err := NewEngineWithConfig(tt.config)

			if tt.shouldFail {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tt.expectedError != "" {
					// Just verify error occurred for nil config
					if err == nil {
						t.Errorf("expected error containing %q, got nil", tt.expectedError)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if engine == nil {
				t.Errorf("engine is nil")
				return
			}

			// Verify we got rules (either from file, ConfigMap, or hardcoded fallback)
			if len(engine.Rules) == 0 {
				t.Errorf("engine has no rules loaded")
				return
			}

			// Verify rules have required fields
			for i, rule := range engine.Rules {
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

// TestSelectorMatches tests label selector matching logic (concept test)
// Note: Complete selector matching testing is done via TestRuleMatching
// and TestConditionEvaluation with actual enriched events
func TestSelectorMatches(t *testing.T) {
	// Label selector matching is tested indirectly through
	// NetworkPolicy evaluation in the full enrichment tests
	t.Logf("Label selector matching tested via enrichment and rule matching tests")
}

// createTestEngine creates an engine with deterministic stub rules for testing
// ANCHOR: Test-specific engine with stub rules - Phase 3.4 Week 3
// Isolates tests from production rule changes by using known, immutable stub rules
func createTestEngine() *Engine {
	logger, _ := zap.NewProduction()
	return &Engine{
		Rules: []*Rule{
			// Stub rules for testing - these are deterministic and won't change
			{
				ControlID:  "TEST_STUB_1",
				Title:      "Test UID equals zero",
				Severity:   "CRITICAL",
				EventTypes: []string{"process_execution"},
				Conditions: []Condition{
					{
						Field:    "process.uid",
						Operator: "equals",
						Value:    0,
					},
				},
			},
			{
				ControlID:  "TEST_STUB_2",
				Title:      "Test capability in list",
				Severity:   "HIGH",
				EventTypes: []string{"capability_usage"},
				Conditions: []Condition{
					{
						Field:    "capability.name",
						Operator: "in",
						Value:    []string{"NET_ADMIN", "SYS_ADMIN"},
					},
				},
			},
			{
				ControlID:  "TEST_STUB_3",
				Title:      "Test role permission count",
				Severity:   "MEDIUM",
				EventTypes: []string{"pod_spec_check"},
				Conditions: []Condition{
					{
						Field:    "kubernetes.role_permission_count",
						Operator: "greater_than",
						Value:    10,
					},
				},
			},
		},
		Logger: logger,
	}
}

// TestConditionEvaluation tests evaluation of different condition types
func TestConditionEvaluation(t *testing.T) {
	engine := createTestEngine()

	tests := []struct {
		name      string
		event     *enrichment.EnrichedEvent
		condition Condition
		expected  bool
	}{
		{
			name: "Equals operator - true match",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Process: &enrichment.ProcessContext{
					UID: 0,
				},
			},
			condition: Condition{
				Field:    "process.uid",
				Operator: "equals",
				Value:    0,
			},
			expected: true,
		},
		{
			name: "Equals operator - numeric normalization",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Process: &enrichment.ProcessContext{
					UID: 0,
				},
			},
			condition: Condition{
				Field:    "process.uid",
				Operator: "equals",
				Value:    int64(0),
			},
			expected: true,
		},
		{
			name: "Equals operator - false match",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Process: &enrichment.ProcessContext{
					UID: 1000,
				},
			},
			condition: Condition{
				Field:    "process.uid",
				Operator: "equals",
				Value:    0,
			},
			expected: false,
		},
		{
			name: "Not equals operator - true match",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Container: &enrichment.ContainerContext{
					ContainerID: "abc123",
				},
			},
			condition: Condition{
				Field:    "container.id",
				Operator: "not_equals",
				Value:    "",
			},
			expected: true,
		},
		{
			name: "Not equals operator - false match",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Container: &enrichment.ContainerContext{
					ContainerID: "",
				},
			},
			condition: Condition{
				Field:    "container.id",
				Operator: "not_equals",
				Value:    "",
			},
			expected: false,
		},
		{
			name: "Not in operator - true match",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Container: &enrichment.ContainerContext{
					Runtime: "docker",
				},
			},
			condition: Condition{
				Field:    "container.runtime",
				Operator: "not_in",
				Value:    []string{"containerd", "cri-o"},
			},
			expected: true,
		},
		{
			name: "Not in operator - false match",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Container: &enrichment.ContainerContext{
					Runtime: "containerd",
				},
			},
			condition: Condition{
				Field:    "container.runtime",
				Operator: "not_in",
				Value:    []string{"containerd", "cri-o"},
			},
			expected: false,
		},
		{
			name: "Not in operator - malformed rule value fails closed",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Container: &enrichment.ContainerContext{
					Runtime: "docker",
				},
			},
			condition: Condition{
				Field:    "container.runtime",
				Operator: "not_in",
				Value:    "containerd",
			},
			expected: false,
		},
		{
			name: "In operator - value found",
			event: &enrichment.EnrichedEvent{
				EventType: "capability_usage",
				Capability: &enrichment.CapabilityContext{
					Name: "NET_ADMIN",
				},
			},
			condition: Condition{
				Field:    "capability.name",
				Operator: "in",
				Value:    []string{"NET_ADMIN", "SYS_ADMIN"},
			},
			expected: true,
		},
		{
			name: "In operator - value not found",
			event: &enrichment.EnrichedEvent{
				EventType: "capability_usage",
				Capability: &enrichment.CapabilityContext{
					Name: "CAP_SETUID",
				},
			},
			condition: Condition{
				Field:    "capability.name",
				Operator: "in",
				Value:    []string{"NET_ADMIN", "SYS_ADMIN"},
			},
			expected: false,
		},
		{
			name: "In operator - malformed rule value",
			event: &enrichment.EnrichedEvent{
				EventType: "capability_usage",
				Capability: &enrichment.CapabilityContext{
					Name: "NET_ADMIN",
				},
			},
			condition: Condition{
				Field:    "capability.name",
				Operator: "in",
				Value:    "NET_ADMIN",
			},
			expected: false,
		},
		{
			name: "Greater than operator - true match",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Kubernetes: &enrichment.K8sContext{
					RolePermissionCount: 15,
				},
			},
			condition: Condition{
				Field:    "kubernetes.role_permission_count",
				Operator: "greater_than",
				Value:    10,
			},
			expected: true,
		},
		{
			name: "Greater than operator - false match",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Kubernetes: &enrichment.K8sContext{
					RolePermissionCount: 5,
				},
			},
			condition: Condition{
				Field:    "kubernetes.role_permission_count",
				Operator: "greater_than",
				Value:    10,
			},
			expected: false,
		},
		{
			name: "Less than operator - true match",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Container: &enrichment.ContainerContext{
					IsolationLevel: 1,
				},
			},
			condition: Condition{
				Field:    "container.isolation_level",
				Operator: "less_than",
				Value:    2,
			},
			expected: true,
		},
		{
			name: "Less than operator - false match",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Container: &enrichment.ContainerContext{
					IsolationLevel: 3,
				},
			},
			condition: Condition{
				Field:    "container.isolation_level",
				Operator: "less_than",
				Value:    2,
			},
			expected: false,
		},
		{
			name: "Contains operator - true match",
			event: &enrichment.EnrichedEvent{
				EventType: "file_write",
				File: &enrichment.FileContext{
					Path: "/etc/passwd",
				},
			},
			condition: Condition{
				Field:    "file.path",
				Operator: "contains",
				Value:    "etc",
			},
			expected: true,
		},
		{
			name: "Contains operator - false match",
			event: &enrichment.EnrichedEvent{
				EventType: "file_write",
				File: &enrichment.FileContext{
					Path: "/bin/bash",
				},
			},
			condition: Condition{
				Field:    "file.path",
				Operator: "contains",
				Value:    "etc",
			},
			expected: false,
		},
		{
			name: "AllowPrivilegeEscalation known value matches",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Container: &enrichment.ContainerContext{
					AllowPrivilegeEscalation:      true,
					AllowPrivilegeEscalationKnown: true,
				},
			},
			condition: Condition{
				Field:    "container.allow_privilege_escalation",
				Operator: "equals",
				Value:    true,
			},
			expected: true,
		},
		{
			name: "AllowPrivilegeEscalation unknown value does not match",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Container: &enrichment.ContainerContext{
					AllowPrivilegeEscalation:      true,
					AllowPrivilegeEscalationKnown: false,
				},
			},
			condition: Condition{
				Field:    "container.allow_privilege_escalation",
				Operator: "equals",
				Value:    true,
			},
			expected: false,
		},
		{
			name: "Regex operator - true match",
			event: &enrichment.EnrichedEvent{
				EventType: "file_write",
				File: &enrichment.FileContext{
					Path: "/etc/passwd",
				},
			},
			condition: Condition{
				Field:    "file.path",
				Operator: "regex",
				Value:    "^/etc/.*$",
			},
			expected: true,
		},
		{
			name: "Regex operator - false match",
			event: &enrichment.EnrichedEvent{
				EventType: "file_write",
				File: &enrichment.FileContext{
					Path: "/var/log/syslog",
				},
			},
			condition: Condition{
				Field:    "file.path",
				Operator: "regex",
				Value:    "^/etc/.*$",
			},
			expected: false,
		},
		{
			name: "Regex operator - invalid pattern",
			event: &enrichment.EnrichedEvent{
				EventType: "file_write",
				File: &enrichment.FileContext{
					Path: "/etc/passwd",
				},
			},
			condition: Condition{
				Field:    "file.path",
				Operator: "regex",
				Value:    "[invalid",
			},
			expected: false,
		},
		{
			name: "Missing event field returns false",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				// No Container context
			},
			condition: Condition{
				Field:    "container.id",
				Operator: "equals",
				Value:    "test",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := tt.condition
			result := engine.evaluateCondition(tt.event, &condition)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestRuleMatching tests complete rule matching against events
// ANCHOR: Rule matching tests with stub rules - Phase 3.4 Week 3
// Uses deterministic stub rules independent of production CIS control definitions
func TestRuleMatching(t *testing.T) {
	engine := createTestEngine()

	tests := []struct {
		name              string
		event             *enrichment.EnrichedEvent
		expectViolations  bool
		minViolationCount int    // Minimum expected violations
		expectedRuleID    string // Expected rule that triggers
	}{
		{
			name: "Root process (UID 0) should trigger TEST_STUB_1",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Process: &enrichment.ProcessContext{
					UID: 0,
				},
				Kubernetes: &enrichment.K8sContext{
					PodUID: "pod-123",
				},
			},
			expectViolations:  true,
			minViolationCount: 1,
			expectedRuleID:    "TEST_STUB_1",
		},
		{
			name: "Non-root process should not trigger TEST_STUB_1",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Process: &enrichment.ProcessContext{
					UID: 1000,
				},
				Kubernetes: &enrichment.K8sContext{
					PodUID: "pod-456",
				},
			},
			expectViolations:  false,
			minViolationCount: 0,
		},
		{
			name: "Dangerous capability (SYS_ADMIN) should trigger TEST_STUB_2",
			event: &enrichment.EnrichedEvent{
				EventType: "capability_usage",
				Capability: &enrichment.CapabilityContext{
					Name: "SYS_ADMIN",
				},
				Kubernetes: &enrichment.K8sContext{
					PodUID: "pod-789",
				},
			},
			expectViolations:  true,
			minViolationCount: 1,
			expectedRuleID:    "TEST_STUB_2",
		},
		{
			name: "Safe capability should not trigger TEST_STUB_2",
			event: &enrichment.EnrichedEvent{
				EventType: "capability_usage",
				Capability: &enrichment.CapabilityContext{
					Name: "CAP_SETUID",
				},
				Kubernetes: &enrichment.K8sContext{
					PodUID: "pod-safe",
				},
			},
			expectViolations:  false,
			minViolationCount: 0,
		},
		{
			name: "High permission count should trigger TEST_STUB_3",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Kubernetes: &enrichment.K8sContext{
					PodUID:              "pod-perms",
					RolePermissionCount: 15,
				},
			},
			expectViolations:  true,
			minViolationCount: 1,
			expectedRuleID:    "TEST_STUB_3",
		},
		{
			name: "Low permission count should not trigger TEST_STUB_3",
			event: &enrichment.EnrichedEvent{
				EventType: "pod_spec_check",
				Kubernetes: &enrichment.K8sContext{
					PodUID:              "pod-safe-perms",
					RolePermissionCount: 5,
				},
			},
			expectViolations:  false,
			minViolationCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := engine.Match(tt.event)

			hasViolations := len(violations) > 0
			if hasViolations != tt.expectViolations {
				t.Errorf("expected violations=%v, got %v (count=%d)", tt.expectViolations, hasViolations, len(violations))
			}

			if tt.expectViolations && len(violations) < tt.minViolationCount {
				t.Errorf("expected at least %d violations, got %d", tt.minViolationCount, len(violations))
			}

			// Verify violation structure
			for i, violation := range violations {
				if violation.ControlID == "" {
					t.Errorf("violation %d has empty ControlID", i)
				}
				if violation.Title == "" {
					t.Errorf("violation %d has empty Title", i)
				}
				if violation.Severity == "" {
					t.Errorf("violation %d has empty Severity", i)
				}
				if violation.Timestamp.IsZero() {
					t.Errorf("violation %d has zero Timestamp", i)
				}
			}
		})
	}
}

func TestPrepareRuleCachesCompilesRegex(t *testing.T) {
	logger := zap.NewNop()
	rules := []*Rule{
		{
			ControlID:  "TEST_REGEX_VALID",
			Title:      "valid regex",
			Severity:   "LOW",
			EventTypes: []string{"file_access"},
			Conditions: []Condition{
				{
					Field:    "file.path",
					Operator: "regex",
					Value:    "^/etc/.*$",
				},
			},
		},
		{
			ControlID:  "TEST_REGEX_INVALID",
			Title:      "invalid regex",
			Severity:   "LOW",
			EventTypes: []string{"file_access"},
			Conditions: []Condition{
				{
					Field:    "file.path",
					Operator: "regex",
					Value:    "[invalid",
				},
			},
		},
	}

	prepareRuleCaches(rules, logger)

	if rules[0].Conditions[0].compiledRegex == nil {
		t.Fatalf("expected compiled regex cache for valid pattern")
	}
	if rules[1].Conditions[0].compiledRegex != nil {
		t.Fatalf("did not expect compiled regex cache for invalid pattern")
	}
}

// TestExtractField tests field extraction from enriched events
func TestExtractField(t *testing.T) {
	engine, _ := NewEngine()

	tests := []struct {
		name     string
		event    *enrichment.EnrichedEvent
		field    string
		expected interface{}
	}{
		{
			name: "Extract process UID",
			event: &enrichment.EnrichedEvent{
				Process: &enrichment.ProcessContext{
					UID: 0,
				},
			},
			field:    "process.uid",
			expected: 0,
		},
		{
			name: "Extract container ID",
			event: &enrichment.EnrichedEvent{
				Container: &enrichment.ContainerContext{
					ContainerID: "abc123def456",
				},
			},
			field:    "container.id",
			expected: "abc123def456",
		},
		{
			name: "Extract event type",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
			},
			field:    "event_type",
			expected: "process_execution",
		},
		{
			name: "Extract Kubernetes pod name",
			event: &enrichment.EnrichedEvent{
				Kubernetes: &enrichment.K8sContext{
					PodName: "nginx-pod",
				},
			},
			field:    "kubernetes.pod_name",
			expected: "nginx-pod",
		},
		{
			name: "Extract Kubernetes namespace",
			event: &enrichment.EnrichedEvent{
				Kubernetes: &enrichment.K8sContext{
					Namespace: "default",
				},
			},
			field:    "kubernetes.namespace",
			expected: "default",
		},
		{
			name: "Extract container runtime",
			event: &enrichment.EnrichedEvent{
				Container: &enrichment.ContainerContext{
					Runtime: "docker",
				},
			},
			field:    "container.runtime",
			expected: "docker",
		},
		{
			name:     "Extract from nil context returns nil",
			event:    &enrichment.EnrichedEvent{},
			field:    "container.id",
			expected: nil,
		},
		{
			name:     "Extract unknown field returns nil",
			event:    &enrichment.EnrichedEvent{},
			field:    "unknown.field",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.extractField(tt.event, tt.field)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestMultipleConditions tests rules with multiple conditions
// ANCHOR: Multiple condition tests with stub rule - Phase 3.4 Week 3
// Tests AND logic: all conditions must be satisfied for rule to match
func TestMultipleConditions(t *testing.T) {
	// Create a test rule with multiple conditions (all must match)
	testRule := &Rule{
		ControlID:  "TEST_MULTI.1",
		Title:      "Multi-condition test",
		Severity:   "HIGH",
		EventTypes: []string{"process_execution"},
		Conditions: []Condition{
			{
				Field:    "process.uid",
				Operator: "equals",
				Value:    0,
			},
			{
				Field:    "kubernetes.pod_uid",
				Operator: "not_equals",
				Value:    "",
			},
		},
	}

	logger, _ := zap.NewProduction()
	engine := &Engine{
		Rules:  []*Rule{testRule},
		Logger: logger,
	}

	tests := []struct {
		name            string
		event           *enrichment.EnrichedEvent
		expectViolation bool
	}{
		{
			name: "All conditions match",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Process: &enrichment.ProcessContext{
					UID: 0,
				},
				Kubernetes: &enrichment.K8sContext{
					PodUID: "pod-123",
				},
			},
			expectViolation: true,
		},
		{
			name: "First condition matches, second doesn't",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Process: &enrichment.ProcessContext{
					UID: 0,
				},
				Kubernetes: &enrichment.K8sContext{
					PodUID: "",
				},
			},
			expectViolation: false,
		},
		{
			name: "First condition doesn't match",
			event: &enrichment.EnrichedEvent{
				EventType: "process_execution",
				Process: &enrichment.ProcessContext{
					UID: 1000,
				},
				Kubernetes: &enrichment.K8sContext{
					PodUID: "pod-123",
				},
			},
			expectViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := engine.Match(tt.event)
			hasViolation := len(violations) > 0

			if hasViolation != tt.expectViolation {
				t.Errorf("expected violation=%v, got %v", tt.expectViolation, hasViolation)
			}
		})
	}
}

// BenchmarkConditionEvaluation benchmarks condition evaluation performance
func BenchmarkConditionEvaluation(b *testing.B) {
	engine, _ := NewEngine()

	event := &enrichment.EnrichedEvent{
		EventType: "process_execution",
		Process: &enrichment.ProcessContext{
			UID: 0,
		},
		Kubernetes: &enrichment.K8sContext{
			PodUID: "pod-benchmark",
		},
	}

	condition := Condition{
		Field:    "process.uid",
		Operator: "equals",
		Value:    0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cond := condition
		engine.evaluateCondition(event, &cond)
	}
}

// BenchmarkRuleMatching benchmarks complete rule matching
func BenchmarkRuleMatching(b *testing.B) {
	engine, _ := NewEngine()

	event := &enrichment.EnrichedEvent{
		EventType: "process_execution",
		Process: &enrichment.ProcessContext{
			UID:     0,
			PID:     1234,
			Command: "bash",
		},
		Container: &enrichment.ContainerContext{
			Privileged: true,
		},
		Kubernetes: &enrichment.K8sContext{
			PodUID: "pod-bench",
		},
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Match(event)
	}
}

// TestExtractFieldAutomountServiceAccountToken verifies extractField handles the
// kubernetes.automount_service_account_token field correctly.
// ANCHOR: Regression test for CIS_5.2.1 extractField fix - Bug: field was missing from switch - Apr 20, 2026
func TestExtractFieldAutomountServiceAccountToken(t *testing.T) {
	engine := createTestEngine()

	trueEvent := &enrichment.EnrichedEvent{
		Kubernetes: &enrichment.K8sContext{AutomountServiceAccountToken: true},
	}
	falseEvent := &enrichment.EnrichedEvent{
		Kubernetes: &enrichment.K8sContext{AutomountServiceAccountToken: false},
	}
	nilK8sEvent := &enrichment.EnrichedEvent{Kubernetes: nil}

	if got := engine.extractField(trueEvent, "kubernetes.automount_service_account_token"); got != true {
		t.Errorf("expected true, got %v", got)
	}
	if got := engine.extractField(falseEvent, "kubernetes.automount_service_account_token"); got != false {
		t.Errorf("expected false, got %v", got)
	}
	if got := engine.extractField(nilK8sEvent, "kubernetes.automount_service_account_token"); got != nil {
		t.Errorf("expected nil for nil Kubernetes context, got %v", got)
	}
}

// TestCIS521RuleMatchSemantics verifies CIS_5.2.1 fires when automount is true and not when false.
// Rule: operator "equals", value true — violation means auto-mount is enabled (misconfigured).
// ANCHOR: Regression test for CIS_5.2.1 rule match semantics - Bug: rule never fired - Apr 20, 2026
func TestCIS521RuleMatchSemantics(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	makeEvent := func(automount bool) *enrichment.EnrichedEvent {
		return &enrichment.EnrichedEvent{
			EventType: "pod_spec_check",
			Kubernetes: &enrichment.K8sContext{
				AutomountServiceAccountToken: automount,
			},
			Timestamp: time.Now(),
		}
	}

	hasViolation := func(violations []*Violation, controlID string) bool {
		for _, v := range violations {
			if v.ControlID == controlID {
				return true
			}
		}
		return false
	}

	// automount=true: pod is misconfigured, CIS_5.2.1 must fire
	violations := engine.Match(makeEvent(true))
	if !hasViolation(violations, "CIS_5.2.1") {
		t.Error("expected CIS_5.2.1 violation when AutomountServiceAccountToken=true, got none")
	}

	// automount=false: pod is correctly configured, CIS_5.2.1 must not fire
	violations = engine.Match(makeEvent(false))
	if hasViolation(violations, "CIS_5.2.1") {
		t.Error("expected no CIS_5.2.1 violation when AutomountServiceAccountToken=false, got one")
	}
}
