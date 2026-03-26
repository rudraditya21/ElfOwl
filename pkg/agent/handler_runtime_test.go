package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/evidence"
	"github.com/udyansh/elf-owl/pkg/rules"
)

type enrichCallback func(context.Context, interface{}) (*enrichment.EnrichedEvent, error)

type runtimeMockEnricher struct {
	processFn    enrichCallback
	networkFn    enrichCallback
	dnsFn        enrichCallback
	fileFn       enrichCallback
	capabilityFn enrichCallback
}

func (m *runtimeMockEnricher) EnrichProcessEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.processFn != nil {
		return m.processFn(ctx, rawEvent)
	}
	return nil, nil
}

func (m *runtimeMockEnricher) EnrichNetworkEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.networkFn != nil {
		return m.networkFn(ctx, rawEvent)
	}
	return nil, nil
}

func (m *runtimeMockEnricher) EnrichDNSEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.dnsFn != nil {
		return m.dnsFn(ctx, rawEvent)
	}
	return nil, nil
}

func (m *runtimeMockEnricher) EnrichFileEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.fileFn != nil {
		return m.fileFn(ctx, rawEvent)
	}
	return nil, nil
}

func (m *runtimeMockEnricher) EnrichCapabilityEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	if m.capabilityFn != nil {
		return m.capabilityFn(ctx, rawEvent)
	}
	return nil, nil
}

type runtimeMockMetrics struct {
	hostDiscarded       int64
	k8sLookupDiscarded  int64
	enrichmentError     int64
	eventProcessed      int64
	violationsFound     int64
}

func (m *runtimeMockMetrics) RecordEventProcessed() {
	atomic.AddInt64(&m.eventProcessed, 1)
}

func (m *runtimeMockMetrics) RecordViolationsFound(n int) {
	atomic.AddInt64(&m.violationsFound, int64(n))
}

func (m *runtimeMockMetrics) RecordEnrichmentError() {
	atomic.AddInt64(&m.enrichmentError, 1)
}

func (m *runtimeMockMetrics) RecordHostEventDiscarded() {
	atomic.AddInt64(&m.hostDiscarded, 1)
}

func (m *runtimeMockMetrics) RecordK8sLookupFailedDiscarded() {
	atomic.AddInt64(&m.k8sLookupDiscarded, 1)
}

func (m *runtimeMockMetrics) SetEventsBuffered(count int) {}

type handlerSpec struct {
	name      string
	eventType string
	invoke    func(*Agent, context.Context, *enrichment.EnrichedEvent)
	setFn     func(*runtimeMockEnricher, enrichCallback)
}

// ANCHOR: Real handler runtime behavior tests - Fix PR-23 #4 - Mar 25, 2026
// Verifies real agent handler methods (not simulated branches) for discard/fallback behavior.
func TestHandlerRuntimeBehaviorMatrix(t *testing.T) {
	apiErr := errors.New("k8s api timeout")

	handlers := []handlerSpec{
		{
			name:      "process",
			eventType: "process_execution",
			invoke:    (*Agent).handleProcessEvent,
			setFn: func(m *runtimeMockEnricher, fn enrichCallback) {
				m.processFn = fn
			},
		},
		{
			name:      "network",
			eventType: "network_connection",
			invoke:    (*Agent).handleNetworkEvent,
			setFn: func(m *runtimeMockEnricher, fn enrichCallback) {
				m.networkFn = fn
			},
		},
		{
			name:      "dns",
			eventType: "dns_query",
			invoke:    (*Agent).handleDNSEvent,
			setFn: func(m *runtimeMockEnricher, fn enrichCallback) {
				m.dnsFn = fn
			},
		},
		{
			name:      "file",
			eventType: "file_access",
			invoke:    (*Agent).handleFileEvent,
			setFn: func(m *runtimeMockEnricher, fn enrichCallback) {
				m.fileFn = fn
			},
		},
		{
			name:      "capability",
			eventType: "capability_usage",
			invoke:    (*Agent).handleCapabilityEvent,
			setFn: func(m *runtimeMockEnricher, fn enrichCallback) {
				m.capabilityFn = fn
			},
		},
	}

	scenarios := []struct {
		name                    string
		kubernetesOnly          bool
		err                     error
		returnEnriched          bool
		wantDiscarded           int64
		wantK8sLookupDiscarded  int64
		wantEnrichmentErrors    int64
		wantProcessed           int64
		wantBuffered            int
		wantRawFallback         bool
	}{
		{
			name:                   "no_pod_discard_when_kubernetes_only_true",
			kubernetesOnly:         true,
			err:                    enrichment.ErrNoKubernetesContext,
			returnEnriched:         false,
			wantDiscarded:          1,
			wantK8sLookupDiscarded: 0,
			wantProcessed:          0,
			wantBuffered:           0,
			wantRawFallback:        false,
		},
		{
			name:                   "no_pod_forward_partial_when_kubernetes_only_false",
			kubernetesOnly:         false,
			err:                    enrichment.ErrNoKubernetesContext,
			returnEnriched:         false,
			wantDiscarded:          0,
			wantK8sLookupDiscarded: 0,
			wantProcessed:          1,
			wantBuffered:           1,
			wantRawFallback:        true,
		},
		{
			name:                    "api_error_discard_when_kubernetes_only_true",
			kubernetesOnly:          true,
			err:                     apiErr,
			returnEnriched:          false,
			wantDiscarded:           0,
			wantK8sLookupDiscarded:  1,
			wantEnrichmentErrors:    1,
			wantProcessed:           0,
			wantBuffered:            0,
			wantRawFallback:         false,
		},
		{
			name:                    "api_error_forward_partial_when_kubernetes_only_false",
			kubernetesOnly:          false,
			err:                     apiErr,
			returnEnriched:          false,
			wantDiscarded:           0,
			wantK8sLookupDiscarded:  0,
			wantEnrichmentErrors:    1,
			wantProcessed:           1,
			wantBuffered:            1,
			wantRawFallback:         true,
		},
		{
			name:                   "success_forward_enriched_event",
			kubernetesOnly:         true,
			err:                    nil,
			returnEnriched:         true,
			wantDiscarded:          0,
			wantK8sLookupDiscarded: 0,
			wantProcessed:          1,
			wantBuffered:           1,
			wantRawFallback:        false,
		},
	}

	for _, handler := range handlers {
		for _, scenario := range scenarios {
			t.Run(handler.name+"_"+scenario.name, func(t *testing.T) {
				mockEnricher := &runtimeMockEnricher{}
				mockMetrics := &runtimeMockMetrics{}

				rawEvent := &enrichment.EnrichedEvent{
					RawEvent:   map[string]interface{}{"pid": uint32(1234)},
					EventType:  handler.eventType,
					Timestamp:  time.Now(),
					Kubernetes: &enrichment.K8sContext{},
				}
				returnedEvent := &enrichment.EnrichedEvent{
					RawEvent:   rawEvent.RawEvent,
					EventType:  handler.eventType,
					Timestamp:  rawEvent.Timestamp,
					Kubernetes: &enrichment.K8sContext{PodUID: "pod-uid"},
				}

				handler.setFn(mockEnricher, func(ctx context.Context, event interface{}) (*enrichment.EnrichedEvent, error) {
					if scenario.returnEnriched {
						return returnedEvent, scenario.err
					}
					return nil, scenario.err
				})

				agent := &Agent{
					Config: &Config{
						Agent: AgentConfig{
							Enrichment: EnrichmentConfig{
								KubernetesOnly: scenario.kubernetesOnly,
							},
						},
					},
					Logger:          zap.NewNop(),
					RuleEngine:      &rules.Engine{},
					Enricher:        mockEnricher,
					EventBuffer:     evidence.NewBuffer(8, time.Second),
					MetricsRegistry: mockMetrics,
				}

				handler.invoke(agent, context.Background(), rawEvent)

				if got := atomic.LoadInt64(&mockMetrics.hostDiscarded); got != scenario.wantDiscarded {
					t.Fatalf("host discarded: got %d, want %d", got, scenario.wantDiscarded)
				}
			if got := atomic.LoadInt64(&mockMetrics.k8sLookupDiscarded); got != scenario.wantK8sLookupDiscarded {
				t.Fatalf("k8s lookup discarded: got %d, want %d", got, scenario.wantK8sLookupDiscarded)
			}
				if got := atomic.LoadInt64(&mockMetrics.enrichmentError); got != scenario.wantEnrichmentErrors {
					t.Fatalf("enrichment errors: got %d, want %d", got, scenario.wantEnrichmentErrors)
				}
				if got := atomic.LoadInt64(&mockMetrics.eventProcessed); got != scenario.wantProcessed {
					t.Fatalf("events processed: got %d, want %d", got, scenario.wantProcessed)
				}

				buffered := agent.EventBuffer.Flush()
				if len(buffered) != scenario.wantBuffered {
					t.Fatalf("buffered events: got %d, want %d", len(buffered), scenario.wantBuffered)
				}
				if scenario.wantBuffered == 1 {
					gotEvent := buffered[0].EnrichedEvent
					if scenario.wantRawFallback && gotEvent != rawEvent {
						t.Fatalf("expected raw fallback event pointer, got different event")
					}
					if !scenario.wantRawFallback && gotEvent != returnedEvent {
						t.Fatalf("expected returned enriched event pointer, got different event")
					}
				}
			})
		}
	}
}
