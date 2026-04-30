// ANCHOR: WebhookPusher unit tests - Test Plan verification - Apr 30, 2026
// Covers: delivery of all 6 event types, lifecycle guards, config validation,
// expandSentinelVars behaviour, and shutdown drain guarantee.

package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/rules"
)

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

func nopLogger() *zap.Logger { return zap.NewNop() }

// minimalCfg returns a WebhookConfig with safe non-zero values pointing at url.
func minimalCfg(url string) WebhookConfig {
	return WebhookConfig{
		Enabled:       true,
		TargetURL:     url,
		BatchSize:     50,
		FlushInterval: 100 * time.Millisecond,
		Timeout:       5 * time.Second,
	}
}

// enrichedEvent builds a minimal EnrichedEvent for the given raw event type string.
func enrichedEvent(eventType string) *enrichment.EnrichedEvent {
	return &enrichment.EnrichedEvent{
		EventType: eventType,
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			PodName:   "test-pod",
			Namespace: "default",
		},
		Process: &enrichment.ProcessContext{PID: 1234, Command: "test"},
	}
}

// collectBatches starts an httptest.Server that collects every JSON batch it
// receives and returns the server together with a function that drains collected
// batches. The server accepts N requests then stops accepting.
func collectServer(t *testing.T) (srv *httptest.Server, batches func() [][]WebhookEvent) {
	t.Helper()
	var collected [][]WebhookEvent
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Logf("server: read body error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var batch []WebhookEvent
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Logf("server: unmarshal error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		collected = append(collected, batch)
		w.WriteHeader(http.StatusOK)
	}))
	return srv, func() [][]WebhookEvent { return collected }
}

// -----------------------------------------------------------------------
// Test Plan item 1 — all 6 event types delivered to listener (no-K8s mode)
// -----------------------------------------------------------------------

// ANCHOR: TestWebhookPusherAllSixEventTypes - Test Plan item 1: no-K8s mode delivery - Apr 30, 2026
// Verifies that Send() for each of the six canonical event types results in a
// WebhookEvent reaching the ingest listener with the correct Type field.
func TestWebhookPusherAllSixEventTypes(t *testing.T) {
	srv, getBatches := collectServer(t)
	defer srv.Close()

	p := NewWebhookPusher(minimalCfg(srv.URL), "test-cluster", "elf-owl-dev", nopLogger())
	p.Start(t.Context())

	eventTypes := []string{
		"process_execution",
		"network_connection",
		"file_access",
		"dns_query",
		"capability_usage",
		"tls_client_hello",
	}

	for _, et := range eventTypes {
		p.Send(enrichedEvent(et), nil)
	}

	p.Stop()

	// Collect all events across all batches.
	var received []WebhookEvent
	for _, batch := range getBatches() {
		received = append(received, batch...)
	}

	if len(received) != len(eventTypes) {
		t.Fatalf("expected %d events, got %d", len(eventTypes), len(received))
	}

	got := make(map[string]bool, len(received))
	for _, e := range received {
		got[string(e.Type)] = true
	}
	for _, et := range eventTypes {
		if !got[et] {
			t.Errorf("event type %q not found in delivered events", et)
		}
	}
}

// -----------------------------------------------------------------------
// Test Plan item 1 (extended) — event fields populated correctly
// -----------------------------------------------------------------------

// ANCHOR: TestWebhookPusherEventFieldsPopulated - Test Plan item 1: field population - Apr 30, 2026
// Verifies that cluster_id, node_name, and timestamp are set on delivered events,
// and that Kubernetes pod/namespace context from the enriched event is present.
func TestWebhookPusherEventFieldsPopulated(t *testing.T) {
	srv, getBatches := collectServer(t)
	defer srv.Close()

	p := NewWebhookPusher(minimalCfg(srv.URL), "prod-cluster", "elf-owl-dev", nopLogger())
	p.Start(t.Context())

	ev := enrichedEvent("process_execution")
	ev.Kubernetes = &enrichment.K8sContext{
		PodName:   "alpine-pod",
		Namespace: "kube-system",
		Image:     "alpine:3.18",
	}
	p.Send(ev, nil)
	p.Stop()

	var received []WebhookEvent
	for _, batch := range getBatches() {
		received = append(received, batch...)
	}
	if len(received) == 0 {
		t.Fatal("no events received")
	}

	e := received[0]
	if e.ClusterID != "prod-cluster" {
		t.Errorf("ClusterID: got %q, want %q", e.ClusterID, "prod-cluster")
	}
	if e.NodeName != "elf-owl-dev" {
		t.Errorf("NodeName: got %q, want %q", e.NodeName, "elf-owl-dev")
	}
	if e.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}
	if e.Metadata.Workload.PodName != "alpine-pod" {
		t.Errorf("Workload.PodName: got %q, want %q", e.Metadata.Workload.PodName, "alpine-pod")
	}
	if e.Metadata.Workload.Namespace != "kube-system" {
		t.Errorf("Workload.Namespace: got %q, want %q", e.Metadata.Workload.Namespace, "kube-system")
	}
	if e.Metadata.Workload.Image != "alpine:3.18" {
		t.Errorf("Workload.Image: got %q, want %q", e.Metadata.Workload.Image, "alpine:3.18")
	}
}

// -----------------------------------------------------------------------
// Test Plan item 3 — go test ./pkg/agent/... passes (lifecycle guards)
// -----------------------------------------------------------------------

// ANCHOR: TestWebhookPusherStartIdempotent - Bug #2: duplicate goroutine on double Start - Apr 30, 2026
func TestWebhookPusherStartIdempotent(t *testing.T) {
	srv, getBatches := collectServer(t)
	defer srv.Close()

	p := NewWebhookPusher(minimalCfg(srv.URL), "c", "n", nopLogger())
	p.Start(t.Context())
	p.Start(t.Context()) // second call must be a no-op
	p.Start(t.Context()) // third call must be a no-op

	p.Send(enrichedEvent("process_execution"), nil)
	p.Stop()

	var total int
	for _, batch := range getBatches() {
		total += len(batch)
	}
	if total != 1 {
		t.Errorf("expected exactly 1 event, got %d (duplicate goroutines would deliver more)", total)
	}
}

// ANCHOR: TestWebhookPusherStopIdempotent - Bug #1: double-close panic on double Stop - Apr 30, 2026
func TestWebhookPusherStopIdempotent(t *testing.T) {
	srv, _ := collectServer(t)
	defer srv.Close()

	p := NewWebhookPusher(minimalCfg(srv.URL), "c", "n", nopLogger())
	p.Start(t.Context())
	p.Stop()

	// Second call must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Stop() panicked on second call: %v", r)
		}
	}()
	p.Stop()
}

// ANCHOR: TestWebhookPusherZeroFlushIntervalClamped - Bug #3: NewTicker(0) panic - Apr 30, 2026
func TestWebhookPusherZeroFlushIntervalClamped(t *testing.T) {
	srv, _ := collectServer(t)
	defer srv.Close()

	cfg := minimalCfg(srv.URL)
	cfg.FlushInterval = 0
	cfg.Timeout = 0

	// Must not panic.
	p := NewWebhookPusher(cfg, "c", "n", nopLogger())
	p.Start(t.Context())
	p.Stop()

	if p.config.FlushInterval <= 0 {
		t.Errorf("FlushInterval not clamped: got %v", p.config.FlushInterval)
	}
	if p.config.Timeout <= 0 {
		t.Errorf("Timeout not clamped: got %v", p.config.Timeout)
	}
}

// ANCHOR: TestWebhookPusherDrainOnStop - Stop() drain guarantee - Apr 30, 2026
// Sends events then immediately calls Stop(); verifies all events are flushed
// to the listener before Stop() returns (drain guarantee).
func TestWebhookPusherDrainOnStop(t *testing.T) {
	srv, getBatches := collectServer(t)
	defer srv.Close()

	cfg := minimalCfg(srv.URL)
	cfg.FlushInterval = 10 * time.Minute // prevent ticker flush; only drain-on-Stop fires
	p := NewWebhookPusher(cfg, "c", "n", nopLogger())
	p.Start(t.Context())

	const n = 5
	for i := 0; i < n; i++ {
		p.Send(enrichedEvent("file_access"), nil)
	}
	p.Stop() // must drain all n events before returning

	var total int
	for _, batch := range getBatches() {
		total += len(batch)
	}
	if total != n {
		t.Errorf("drain on Stop: expected %d events, got %d", n, total)
	}
}

// ANCHOR: TestWebhookPusherBatchSizeFlush - batch size threshold flush - Apr 30, 2026
// Verifies that hitting BatchSize triggers an immediate flush without waiting for ticker.
func TestWebhookPusherBatchSizeFlush(t *testing.T) {
	srv, getBatches := collectServer(t)
	defer srv.Close()

	cfg := minimalCfg(srv.URL)
	cfg.BatchSize = 3
	cfg.FlushInterval = 10 * time.Minute
	p := NewWebhookPusher(cfg, "c", "n", nopLogger())
	p.Start(t.Context())

	for i := 0; i < 3; i++ {
		p.Send(enrichedEvent("network_connection"), nil)
	}

	// Give the flush goroutine a moment to fire and POST.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var total int
		for _, b := range getBatches() {
			total += len(b)
		}
		if total >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	p.Stop()

	var total int
	for _, batch := range getBatches() {
		total += len(batch)
	}
	if total < 3 {
		t.Errorf("batch size flush: expected >= 3 events, got %d", total)
	}
}

// -----------------------------------------------------------------------
// Test Plan item 5 — empty target_url rejected at startup
// -----------------------------------------------------------------------

// ANCHOR: TestValidateRejectsEnabledWebhookWithEmptyURL - Test Plan item 5 - Apr 30, 2026
func TestValidateRejectsEnabledWebhookWithEmptyURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Webhook.Enabled = true
	cfg.Agent.Webhook.TargetURL = ""

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate() to return an error for enabled webhook with empty target_url")
	}
}

// ANCHOR: TestValidateAcceptsEnabledWebhookWithURL - Validate() positive case - Apr 30, 2026
func TestValidateAcceptsEnabledWebhookWithURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Webhook.Enabled = true
	cfg.Agent.Webhook.TargetURL = "http://127.0.0.1:8888/events"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected Validate() to pass for enabled webhook with target_url set, got: %v", err)
	}
}

// ANCHOR: TestValidateRejectsNegativeBatchSize - Bug #14: validation in Validate() - Apr 30, 2026
func TestValidateRejectsNegativeBatchSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Webhook.Enabled = true
	cfg.Agent.Webhook.TargetURL = "http://127.0.0.1:8888/events"
	cfg.Agent.Webhook.BatchSize = -1

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate() to reject negative BatchSize")
	}
}

// ANCHOR: TestValidateRejectsNegativeFlushInterval - Bug #14: validation in Validate() - Apr 30, 2026
func TestValidateRejectsNegativeFlushInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Webhook.Enabled = true
	cfg.Agent.Webhook.TargetURL = "http://127.0.0.1:8888/events"
	cfg.Agent.Webhook.FlushInterval = -1

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate() to reject negative FlushInterval")
	}
}

// -----------------------------------------------------------------------
// Test Plan item 6 — node_name not literal ${HOSTNAME}
// -----------------------------------------------------------------------

// ANCHOR: TestExpandSentinelVarsHostname - Test Plan item 6: node_name not literal ${HOSTNAME} - Apr 30, 2026
// Verifies that expandSentinelVars replaces ${HOSTNAME} and $HOSTNAME with
// the actual value from the environment, not the literal string.
func TestExpandSentinelVarsHostname(t *testing.T) {
	os.Setenv("HOSTNAME", "elf-owl-dev")
	defer os.Unsetenv("HOSTNAME")

	input := "node_name: ${HOSTNAME}"
	got := expandSentinelVars(input)
	want := "node_name: elf-owl-dev"
	if got != want {
		t.Errorf("expandSentinelVars: got %q, want %q", got, want)
	}

	input2 := "node_name: $HOSTNAME"
	got2 := expandSentinelVars(input2)
	if got2 != want {
		t.Errorf("expandSentinelVars bare var: got %q, want %q", got2, want)
	}
}

// ANCHOR: TestExpandSentinelVarsOWLPrefix - only OWL_ and HOSTNAME expanded - Apr 30, 2026
// Verifies that non-sentinel vars (e.g. $PATH, $SECRET_KEY) are NOT expanded,
// preventing env-var injection from arbitrary YAML content.
func TestExpandSentinelVarsOWLPrefix(t *testing.T) {
	os.Setenv("OWL_CLUSTER_ID", "prod-cluster")
	os.Setenv("SECRET_KEY", "should-not-appear")
	defer os.Unsetenv("OWL_CLUSTER_ID")
	defer os.Unsetenv("SECRET_KEY")

	input := "cluster_id: ${OWL_CLUSTER_ID}\npassword: ${SECRET_KEY}"
	got := expandSentinelVars(input)

	if got != "cluster_id: prod-cluster\npassword: ${SECRET_KEY}" {
		t.Errorf("expandSentinelVars: got %q", got)
	}
}

// -----------------------------------------------------------------------
// TLS cert fields propagated into webhook JSON
// -----------------------------------------------------------------------

// ANCHOR: TestWebhookPusherTLSCertFieldsInJSON - Bug: cert_sha256 missing from webhook - Apr 30, 2026
// Regression guard: TLSContext.CertSHA256/CertIssuer/CertExpiry must appear in the delivered
// WebhookEvent JSON under the "tls" key. The bug was that probeCert ran asynchronously so the
// event was queued before the cert arrived; fix was to make certGroup.Do synchronous.
// This test verifies the serialization path end-to-end without needing a real TLS probe.
func TestWebhookPusherTLSCertFieldsInJSON(t *testing.T) {
	srv, getBatches := collectServer(t)
	defer srv.Close()

	p := NewWebhookPusher(minimalCfg(srv.URL), "c", "n", nopLogger())
	p.Start(t.Context())

	ev := enrichedEvent("tls_client_hello")
	ev.TLS = &enrichment.TLSContext{
		JA3Fingerprint: "abc123def456",
		SNI:            "example.com",
		TLSVersion:     "TLS 1.3",
		CertSHA256:     "99:e1:4b:50:aa:bb:cc:dd",
		CertIssuer:     "Let's Encrypt Authority X3",
		CertExpiry:     1800000000,
	}
	p.Send(ev, nil)
	p.Stop()

	var received []WebhookEvent
	for _, batch := range getBatches() {
		received = append(received, batch...)
	}
	if len(received) == 0 {
		t.Fatal("no events received")
	}

	tls := received[0].TLS
	if tls == nil {
		t.Fatal("WebhookEvent.TLS is nil")
	}
	if tls.CertSHA256 != "99:e1:4b:50:aa:bb:cc:dd" {
		t.Errorf("CertSHA256: got %q, want %q", tls.CertSHA256, "99:e1:4b:50:aa:bb:cc:dd")
	}
	if tls.CertIssuer != "Let's Encrypt Authority X3" {
		t.Errorf("CertIssuer: got %q, want %q", tls.CertIssuer, "Let's Encrypt Authority X3")
	}
	if tls.CertExpiry != 1800000000 {
		t.Errorf("CertExpiry: got %d, want %d", tls.CertExpiry, 1800000000)
	}

	// Also verify the JSON bytes contain the cert fields.
	raw, err := json.Marshal(received[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "cert_sha256") {
		t.Errorf("JSON missing cert_sha256: %s", s)
	}
	if !strings.Contains(s, "cert_issuer") {
		t.Errorf("JSON missing cert_issuer: %s", s)
	}
}

// -----------------------------------------------------------------------
// Additional: violations included in delivered event
// -----------------------------------------------------------------------

// ANCHOR: TestWebhookPusherViolationsForwarded - violations attached to event - Apr 30, 2026
func TestWebhookPusherViolationsForwarded(t *testing.T) {
	srv, getBatches := collectServer(t)
	defer srv.Close()

	p := NewWebhookPusher(minimalCfg(srv.URL), "c", "n", nopLogger())
	p.Start(t.Context())

	violations := []*rules.Violation{
		{ControlID: "CIS_5.1.1", Title: "overly permissive RBAC", Severity: "HIGH"},
	}
	p.Send(enrichedEvent("process_execution"), violations)
	p.Stop()

	var received []WebhookEvent
	for _, batch := range getBatches() {
		received = append(received, batch...)
	}
	if len(received) == 0 {
		t.Fatal("no events received")
	}
	if len(received[0].Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(received[0].Violations))
	}
	if received[0].Violations[0].ControlID != "CIS_5.1.1" {
		t.Errorf("ControlID: got %q, want %q", received[0].Violations[0].ControlID, "CIS_5.1.1")
	}
}

// -----------------------------------------------------------------------
// Additional: 4xx response does not panic; body is drained
// -----------------------------------------------------------------------

// ANCHOR: TestWebhookPusherHandles4xx - Bug #5: body drain on error responses - Apr 30, 2026
// Verifies that a 4xx response from the ingest endpoint does not cause a panic
// or goroutine leak, and that subsequent sends still reach the server.
func TestWebhookPusherHandles4xx(t *testing.T) {
	var callCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body) //nolint:errcheck
		n := atomic.AddInt64(&callCount, 1)
		if n == 1 {
			w.WriteHeader(http.StatusUnprocessableEntity) // 422
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := minimalCfg(srv.URL)
	cfg.BatchSize = 1      // flush immediately on each send
	cfg.FlushInterval = 10 * time.Minute
	p := NewWebhookPusher(cfg, "c", "n", nopLogger())
	p.Start(t.Context())

	p.Send(enrichedEvent("dns_query"), nil)   // first POST → 422
	time.Sleep(150 * time.Millisecond)
	p.Send(enrichedEvent("dns_query"), nil)   // second POST → 200
	p.Stop()

	if n := atomic.LoadInt64(&callCount); n < 2 {
		t.Errorf("expected at least 2 server calls (body drain allows reuse), got %d", n)
	}
}

// -----------------------------------------------------------------------
// Additional: redactHeaders masks sensitive keys
// -----------------------------------------------------------------------

// ANCHOR: TestRedactHeaders - Bug #7: auth token redaction - Apr 30, 2026
func TestRedactHeaders(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer supersecret",
		"X-Api-Key":     "key123",
		"X-Auth-Token":  "tok456",
		"Content-Type":  "application/json",
		"X-Request-ID":  "abc",
	}
	redacted := redactHeaders(headers)

	sensitive := []string{"Authorization", "X-Api-Key", "X-Auth-Token"}
	for _, k := range sensitive {
		if redacted[k] != "[redacted]" {
			t.Errorf("key %q: expected [redacted], got %q", k, redacted[k])
		}
	}
	if redacted["Content-Type"] != "application/json" {
		t.Errorf("Content-Type should be unchanged, got %q", redacted["Content-Type"])
	}
	if redacted["X-Request-ID"] != "abc" {
		t.Errorf("X-Request-ID should be unchanged, got %q", redacted["X-Request-ID"])
	}
	// Original map must be unmodified.
	if headers["Authorization"] != "Bearer supersecret" {
		t.Error("original headers map was mutated")
	}
}
