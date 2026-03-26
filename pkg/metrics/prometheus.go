// ANCHOR: Prometheus metrics collection - Dec 26, 2025
// Tracks agent metrics for monitoring and observability

package metrics

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Registry holds all Prometheus metrics for the agent
type Registry struct {
	eventsProcessed   prometheus.Counter
	violationsFound   prometheus.Counter
	eventsBuffered    prometheus.Gauge
	pushSuccess       prometheus.Counter
	pushFailure       prometheus.Counter
	pushLatency       prometheus.Histogram
	enrichmentErrors  prometheus.Counter
	ruleMatchErrors   prometheus.Counter
	// ANCHOR: Host event discard metric - Filter: K8s-native compliance - Mar 24, 2026
	hostEventsDiscarded prometheus.Counter
	// ANCHOR: K8s lookup fail-closed discard metric - Fix PR-23 #7 - Mar 26, 2026
	// Separate from hostEventsDiscarded to distinguish API failures from true host events.
	k8sLookupFailedDiscards prometheus.Counter
}

// NewRegistry creates a new metrics registry
func NewRegistry() *Registry {
	return &Registry{
		eventsProcessed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elf_owl_events_processed_total",
			Help: "Total number of events processed",
		}),
		violationsFound: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elf_owl_violations_found_total",
			Help: "Total number of CIS violations detected",
		}),
		eventsBuffered: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "elf_owl_events_buffered",
			Help: "Current number of events in buffer",
		}),
		pushSuccess: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elf_owl_push_success_total",
			Help: "Total successful push operations",
		}),
		pushFailure: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elf_owl_push_failure_total",
			Help: "Total failed push operations",
		}),
		pushLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "elf_owl_push_latency_seconds",
			Help:    "Push operation latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		enrichmentErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elf_owl_enrichment_errors_total",
			Help: "Total enrichment errors",
		}),
		ruleMatchErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elf_owl_rule_match_errors_total",
			Help: "Total rule matching errors",
		}),
		// ANCHOR: Host event discard metric - Filter: K8s-native compliance - Mar 24, 2026
		hostEventsDiscarded: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elf_owl_host_events_discarded_total",
			Help: "Total host process events discarded due to kubernetes_only filter",
		}),
		// ANCHOR: K8s lookup fail-closed discard counter - Fix PR-23 #7 - Mar 26, 2026
		// Tracks events discarded due to K8s API errors when kubernetes_only=true.
		// Distinct from host_events_discarded which is strictly for non-pod events.
		k8sLookupFailedDiscards: promauto.NewCounter(prometheus.CounterOpts{
			Name: "elf_owl_k8s_lookup_failed_discards_total",
			Help: "Events discarded due to K8s API lookup failures when kubernetes_only=true (fail-closed)",
		}),
	}
}

// RecordEventProcessed records that an event was processed
func (r *Registry) RecordEventProcessed() {
	r.eventsProcessed.Inc()
}

// RecordViolationFound records that a single violation was found
func (r *Registry) RecordViolationFound() {
	r.violationsFound.Inc()
}

// RecordViolationsFound records n violations at once.
//
// ANCHOR: Batch violation counter - Medium finding fix - Feb 18, 2026
// WHY: RecordViolationFound() was called once per event even when the rule
//      engine matched multiple violations, causing elf_owl_violations_found_total
//      to undercount by (n-1) for every multi-violation event.
// WHAT: Use Counter.Add(n) to increment by the actual number of violations.
// HOW: prometheus.Counter.Add() is the idiomatic batch-increment API.
func (r *Registry) RecordViolationsFound(n int) {
	if n > 0 {
		r.violationsFound.Add(float64(n))
	}
}

// SetEventsBuffered sets the current number of buffered events
func (r *Registry) SetEventsBuffered(count int) {
	r.eventsBuffered.Set(float64(count))
}

// RecordPushSuccess records a successful push
func (r *Registry) RecordPushSuccess() {
	r.pushSuccess.Inc()
}

// RecordPushFailure records a failed push
func (r *Registry) RecordPushFailure() {
	r.pushFailure.Inc()
}

// RecordPushLatency records push operation latency
func (r *Registry) RecordPushLatency(seconds float64) {
	r.pushLatency.Observe(seconds)
}

// RecordEnrichmentError records an enrichment error
func (r *Registry) RecordEnrichmentError() {
	r.enrichmentErrors.Inc()
}

// RecordHostEventDiscarded records a host event discarded by kubernetes_only filter
// ANCHOR: Host event discard metric - Filter: K8s-native compliance - Mar 24, 2026
func (r *Registry) RecordHostEventDiscarded() {
	r.hostEventsDiscarded.Inc()
}

// RecordK8sLookupFailedDiscarded records an event discarded because a K8s API lookup
// failed and kubernetes_only=true (fail-closed policy).
// ANCHOR: K8s lookup fail-closed discard recorder - Fix PR-23 #7 - Mar 26, 2026
func (r *Registry) RecordK8sLookupFailedDiscarded() {
	r.k8sLookupFailedDiscards.Inc()
}

// RecordRuleMatchError records a rule matching error
func (r *Registry) RecordRuleMatchError() {
	r.ruleMatchErrors.Inc()
}

// Simple atomic counters as fallback
type SimpleRegistry struct {
	eventsProcessed int64
	violationsFound int64
}

// NewSimpleRegistry creates a simple atomic counter registry
func NewSimpleRegistry() *SimpleRegistry {
	return &SimpleRegistry{}
}

// RecordEventProcessed records an event
func (s *SimpleRegistry) RecordEventProcessed() {
	atomic.AddInt64(&s.eventsProcessed, 1)
}

// RecordViolationFound records a violation
func (s *SimpleRegistry) RecordViolationFound() {
	atomic.AddInt64(&s.violationsFound, 1)
}
