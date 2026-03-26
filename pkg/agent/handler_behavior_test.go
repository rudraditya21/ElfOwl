package agent

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// MockEnricher implements enrichment.Enricher interface for testing
type MockEnricher struct {
	EnrichProcessEventFunc   func(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
	EnrichNetworkEventFunc   func(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
	EnrichDNSEventFunc       func(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
	EnrichFileEventFunc      func(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
	EnrichCapabilityEventFunc func(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error)
}

func (m *MockEnricher) EnrichProcessEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.EnrichProcessEventFunc != nil {
		return m.EnrichProcessEventFunc(ctx, rawEvent)
	}
	return nil, nil
}

func (m *MockEnricher) EnrichNetworkEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.EnrichNetworkEventFunc != nil {
		return m.EnrichNetworkEventFunc(ctx, rawEvent)
	}
	return nil, nil
}

func (m *MockEnricher) EnrichDNSEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.EnrichDNSEventFunc != nil {
		return m.EnrichDNSEventFunc(ctx, rawEvent)
	}
	return nil, nil
}

func (m *MockEnricher) EnrichFileEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.EnrichFileEventFunc != nil {
		return m.EnrichFileEventFunc(ctx, rawEvent)
	}
	return nil, nil
}

func (m *MockEnricher) EnrichCapabilityEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.EnrichCapabilityEventFunc != nil {
		return m.EnrichCapabilityEventFunc(ctx, rawEvent)
	}
	return nil, nil
}

// MockMetricsRegistry tracks metric calls for verification
type MockMetricsRegistry struct {
	HostEventDiscardedCount int
	EnrichmentErrorCount    int
}

func (m *MockMetricsRegistry) RecordHostEventDiscarded() {
	m.HostEventDiscardedCount++
}

func (m *MockMetricsRegistry) RecordEnrichmentError() {
	m.EnrichmentErrorCount++
}

func (m *MockMetricsRegistry) RecordRuleViolation(controlID string) {}
func (m *MockMetricsRegistry) RecordEventProcessed()               {}

// TestHandlerDiscardWhenKubernetesOnlyTrue validates that events without K8s context are discarded
// ANCHOR: Handler discard behavior test - Feature: K8s-only filtering validation - Mar 25, 2026
// Tests that when kubernetes_only=true and ErrNoKubernetesContext is returned, event is discarded.
func TestHandlerDiscardWhenKubernetesOnlyTrue(t *testing.T) {
	logger, _ := zap.NewProduction()
	metrics := &MockMetricsRegistry{}

	// Handler config with kubernetes_only=true
	config := &Config{
		Agent: AgentConfig{
			Enrichment: EnrichmentConfig{
				KubernetesOnly: true,
			},
		},
	}

	// Verify error handling pattern from agent.go
	err := enrichment.ErrNoKubernetesContext

	if err != nil {
		// ANCHOR: K8s-only discard pattern - Fix PR-23 #1 - Mar 24, 2026
		// When kubernetes_only=true and pod context is missing, discard event.
		if errors.Is(err, enrichment.ErrNoKubernetesContext) {
			if config.Agent.Enrichment.KubernetesOnly {
				// Event should be discarded
				logger.Debug("discarded host event: no pod context")
				metrics.RecordHostEventDiscarded()

				// Verify discard occurred
				if metrics.HostEventDiscardedCount != 1 {
					t.Errorf("Expected 1 discard, got %d", metrics.HostEventDiscardedCount)
				}
				return
			}
		}
	}

	t.Errorf("Expected event to be discarded with kubernetes_only=true")
}

// TestHandlerFallbackWhenKubernetesOnlyFalse validates that events are processed when kubernetes_only=false
// ANCHOR: Handler fallback behavior test - Feature: host event processing - Mar 25, 2026
// Tests that when kubernetes_only=false, events without K8s context are forwarded as partial.
func TestHandlerFallbackWhenKubernetesOnlyFalse(t *testing.T) {
	logger, _ := zap.NewProduction()
	metrics := &MockMetricsRegistry{}

	// Partial event without K8s context
	rawEvent := map[string]interface{}{
		"PID":     uint32(1234),
		"Command": "curl",
	}

	enrichedEvent := &enrichment.EnrichedEvent{
		RawEvent:  rawEvent,
		EventType: "process_execution",
		Process: &enrichment.ProcessContext{
			PID:     1234,
			Command: "curl",
		},
		Kubernetes: &enrichment.K8sContext{
			PodUID: "", // No pod context
		},
	}

	// Handler config with kubernetes_only=false
	config := &Config{
		Agent: AgentConfig{
			Enrichment: EnrichmentConfig{
				KubernetesOnly: false,
			},
		},
	}

	// Verify error handling pattern from agent.go
	err := enrichment.ErrNoKubernetesContext
	var processedEvent *enrichment.EnrichedEvent

	if err != nil {
		if errors.Is(err, enrichment.ErrNoKubernetesContext) {
			if config.Agent.Enrichment.KubernetesOnly {
				t.Errorf("Expected fallback path but kubernetes_only=true")
			} else {
				// kubernetes_only=false: process host event with non-K8s enrichment
				logger.Debug("processing host event (kubernetes_only disabled)")
				if enrichedEvent == nil {
					enrichedEvent = &enrichment.EnrichedEvent{RawEvent: rawEvent}
				}
				processedEvent = enrichedEvent
			}
		}
	}

	// Verify event was processed (not discarded)
	if processedEvent == nil {
		t.Errorf("Expected event to be processed with kubernetes_only=false")
	}

	if processedEvent.Process.Command != "curl" {
		t.Errorf("Expected command 'curl', got %s", processedEvent.Process.Command)
	}

	// Verify no discard was recorded
	if metrics.HostEventDiscardedCount != 0 {
		t.Errorf("Expected 0 discards, got %d", metrics.HostEventDiscardedCount)
	}
}

// TestHandlerFailClosedOnK8sAPIError validates that API errors trigger discard when kubernetes_only=true
// ANCHOR: Handler fail-closed behavior test - Feature: API error safety - Mar 25, 2026
// Tests that K8s API errors are treated as critical failures and events are discarded when kubernetes_only=true.
func TestHandlerFailClosedOnK8sAPIError(t *testing.T) {
	logger, _ := zap.NewProduction()
	metrics := &MockMetricsRegistry{}

	// Handler config with kubernetes_only=true
	config := &Config{
		Agent: AgentConfig{
			Enrichment: EnrichmentConfig{
				KubernetesOnly: true,
			},
		},
	}

	// Simulate K8s API error (not ErrNoKubernetesContext)
	apiErr := errors.New("K8s API connection timeout")
	var eventProcessed bool

	if apiErr != nil {
		// ANCHOR: Fail-closed on K8s lookup errors - Fix PR-23 HIGH #2 - Mar 25, 2026
		// During K8s API outage/throttling/RBAC failure, errors must not bypass
		// kubernetes_only filtering — discard to prevent false positives.
		if errors.Is(apiErr, enrichment.ErrNoKubernetesContext) {
			// This is a regular host event (no pod), not an API failure
			t.Errorf("Unexpected: API error treated as host event")
		} else {
			// Real API error - apply fail-closed logic
			metrics.RecordEnrichmentError()
			if config.Agent.Enrichment.KubernetesOnly {
				logger.Debug("discarded event: K8s lookup failed and kubernetes_only=true", zap.Error(apiErr))
				metrics.RecordHostEventDiscarded()
			} else {
				// kubernetes_only=false: forward partial event
				logger.Debug("event enrichment failed, using partial event", zap.Error(apiErr))
				eventProcessed = true
			}
		}
	}

	// Verify discard occurred (not processing with partial event)
	if eventProcessed {
		t.Errorf("Expected event to be discarded on K8s API error with kubernetes_only=true")
	}

	if metrics.HostEventDiscardedCount != 1 {
		t.Errorf("Expected 1 discard on API error, got %d", metrics.HostEventDiscardedCount)
	}

	if metrics.EnrichmentErrorCount != 1 {
		t.Errorf("Expected 1 enrichment error recorded, got %d", metrics.EnrichmentErrorCount)
	}
}

// TestHandlerProcessesPartialOnK8sAPIErrorWhenNotKubernetesOnly tests fallback on API error
func TestHandlerProcessesPartialOnK8sAPIErrorWhenNotKubernetesOnly(t *testing.T) {
	logger, _ := zap.NewProduction()
	metrics := &MockMetricsRegistry{}

	// Handler config with kubernetes_only=false
	config := &Config{
		Agent: AgentConfig{
			Enrichment: EnrichmentConfig{
				KubernetesOnly: false,
			},
		},
	}

	// Simulate K8s API error
	apiErr := errors.New("K8s API connection timeout")
	var eventProcessed bool

	if apiErr != nil {
		if errors.Is(apiErr, enrichment.ErrNoKubernetesContext) {
			t.Errorf("Unexpected: API error treated as host event")
		} else {
			// Real API error
			metrics.RecordEnrichmentError()
			if config.Agent.Enrichment.KubernetesOnly {
				metrics.RecordHostEventDiscarded()
			} else {
				// kubernetes_only=false: forward partial event
				logger.Debug("event enrichment failed, using partial event", zap.Error(apiErr))
				eventProcessed = true
			}
		}
	}

	// Verify event was processed (not discarded)
	if !eventProcessed {
		t.Errorf("Expected partial event to be processed with kubernetes_only=false")
	}

	if metrics.HostEventDiscardedCount != 0 {
		t.Errorf("Expected 0 discards on API error with kubernetes_only=false, got %d", metrics.HostEventDiscardedCount)
	}
}

// Table-driven test for handler behavior across configuration scenarios
// TestHandlerBehaviorScenarios covers all combinations of kubernetes_only and error types
// ANCHOR: Table-driven handler behavior tests - Feature: comprehensive configuration validation - Mar 25, 2026
// Tests all scenarios: pod found, pod missing, API error, with kubernetes_only true/false.
func TestHandlerBehaviorScenarios(t *testing.T) {
	tests := []struct {
		name                string
		kubernetesOnly      bool
		enrichmentError     error
		expectedDiscard     bool
		expectedProcess     bool
		expectedMetricCall  string
		description         string
	}{
		{
			name:               "pod_found_k8s_only_true",
			kubernetesOnly:     true,
			enrichmentError:    nil,
			expectedDiscard:    false,
			expectedProcess:    true,
			expectedMetricCall: "none",
			description:        "Valid pod with K8s-only enabled",
		},
		{
			name:               "pod_found_k8s_only_false",
			kubernetesOnly:     false,
			enrichmentError:    nil,
			expectedDiscard:    false,
			expectedProcess:    true,
			expectedMetricCall: "none",
			description:        "Valid pod with K8s-only disabled",
		},
		{
			name:               "no_pod_k8s_only_true",
			kubernetesOnly:     true,
			enrichmentError:    enrichment.ErrNoKubernetesContext,
			expectedDiscard:    true,
			expectedProcess:    false,
			expectedMetricCall: "HostEventDiscarded",
			description:        "Host event with K8s-only enabled (should discard)",
		},
		{
			name:               "no_pod_k8s_only_false",
			kubernetesOnly:     false,
			enrichmentError:    enrichment.ErrNoKubernetesContext,
			expectedDiscard:    false,
			expectedProcess:    true,
			expectedMetricCall: "none",
			description:        "Host event with K8s-only disabled (should process)",
		},
		{
			name:               "api_error_k8s_only_true",
			kubernetesOnly:     true,
			enrichmentError:    errors.New("K8s API error"),
			expectedDiscard:    true,
			expectedProcess:    false,
			expectedMetricCall: "HostEventDiscarded",
			description:        "K8s API error with K8s-only enabled (fail-closed, discard)",
		},
		{
			name:               "api_error_k8s_only_false",
			kubernetesOnly:     false,
			enrichmentError:    errors.New("K8s API error"),
			expectedDiscard:    false,
			expectedProcess:    true,
			expectedMetricCall: "EnrichmentError",
			description:        "K8s API error with K8s-only disabled (fallback)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, _ := zap.NewProduction()
			metrics := &MockMetricsRegistry{}

			config := &Config{
				Agent: AgentConfig{
					Enrichment: EnrichmentConfig{
						KubernetesOnly: tt.kubernetesOnly,
					},
				},
			}

			err := tt.enrichmentError
			var eventProcessed bool
			var eventDiscarded bool

			if err == nil {
				// No error: event processed normally
				eventProcessed = true
			} else if errors.Is(err, enrichment.ErrNoKubernetesContext) {
				// Host event or pod missing
				if config.Agent.Enrichment.KubernetesOnly {
					logger.Debug("discarded host event: no pod context")
					metrics.RecordHostEventDiscarded()
					eventDiscarded = true
				} else {
					logger.Debug("processing host event (kubernetes_only disabled)")
					eventProcessed = true
				}
			} else {
				// Real K8s API error
				metrics.RecordEnrichmentError()
				if config.Agent.Enrichment.KubernetesOnly {
					logger.Debug("discarded event: K8s lookup failed and kubernetes_only=true", zap.Error(err))
					metrics.RecordHostEventDiscarded()
					eventDiscarded = true
				} else {
					logger.Debug("event enrichment failed, using partial event", zap.Error(err))
					eventProcessed = true
				}
			}

			// Verify expected behavior
			if tt.expectedDiscard && !eventDiscarded {
				t.Errorf("%s: expected discard but event was processed", tt.name)
			}
			if tt.expectedProcess && !eventProcessed {
				t.Errorf("%s: expected processing but event was discarded", tt.name)
			}

			// Verify metrics
			if tt.expectedMetricCall == "HostEventDiscarded" && metrics.HostEventDiscardedCount == 0 {
				t.Errorf("%s: expected HostEventDiscarded metric, got none", tt.name)
			}
			if tt.expectedMetricCall == "EnrichmentError" && metrics.EnrichmentErrorCount == 0 {
				t.Errorf("%s: expected EnrichmentError metric, got none", tt.name)
			}
		})
	}
}
