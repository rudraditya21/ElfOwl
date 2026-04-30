// ANCHOR: Outbound webhook pusher - Feature: ClickHouse event push - Apr 29, 2026
// Batches all enriched events from every eBPF monitor and POSTs them as a JSON array
// to a configured target_url so an external ingest program can store them in ClickHouse.

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/rules"
)

// EventType identifies the kind of security event in a WebhookEvent payload.
type EventType string

const (
	EventTypeProcess    EventType = "process_execution"
	EventTypeNetwork    EventType = "network_connection"
	EventTypeDNS        EventType = "dns_query"
	EventTypeFile       EventType = "file_access"
	EventTypeCapability EventType = "capability_usage"
	EventTypeTLS        EventType = "tls_client_hello"
)

// ViolationSummary is a full violation record embedded in the webhook payload.
type ViolationSummary struct {
	ControlID      string `json:"control_id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Description    string `json:"description,omitempty"`
	RemediationRef string `json:"remediation_ref,omitempty"`
}

// -----------------------------------------------------------------------
// Metadata structs
// -----------------------------------------------------------------------

// SeverityDistribution counts violations by severity bucket.
type SeverityDistribution struct {
	Critical int `json:"CRITICAL"`
	High     int `json:"HIGH"`
	Medium   int `json:"MEDIUM"`
	Low      int `json:"LOW"`
}

// WorkloadMeta flattens K8s + container identity for easy ClickHouse columns.
type WorkloadMeta struct {
	Namespace      string `json:"namespace"`
	PodName        string `json:"pod_name"`
	PodUID         string `json:"pod_uid"`
	ContainerName  string `json:"container_name"`
	ContainerID    string `json:"container_id"`
	Image          string `json:"image"`
	ImageRegistry  string `json:"image_registry"`
	ImageTag       string `json:"image_tag"`
	ServiceAccount string `json:"service_account"`
	OwnerKind      string `json:"owner_kind"`
	OwnerName      string `json:"owner_name"`
}

// SecurityPosture consolidates all security context flags into one queryable object.
type SecurityPosture struct {
	Privileged                 bool   `json:"privileged"`
	RunAsRoot                  bool   `json:"run_as_root"`
	AllowPrivilegeEscalation   bool   `json:"allow_privilege_escalation"`
	HostNetwork                bool   `json:"host_network"`
	HostPID                    bool   `json:"host_pid"`
	HostIPC                    bool   `json:"host_ipc"`
	ReadOnlyFilesystem         bool   `json:"read_only_filesystem"`
	KernelHardening            bool   `json:"kernel_hardening"`
	SeccompProfile             string `json:"seccomp_profile"`
	ApparmorProfile            string `json:"apparmor_profile"`
	RBACLevel                  int    `json:"rbac_level"`
	RBACEnforced               bool   `json:"rbac_enforced"`
	AutomountServiceAccountToken bool  `json:"automount_sa_token"`
	HasNetworkPolicy           bool   `json:"has_network_policy"`
	ServiceAccountPermissions  int    `json:"service_account_permissions"`
	ImageSigned                bool   `json:"image_signed"`
	ImageScanStatus            string `json:"image_scan_status"`
}

// ProcessDetail carries flat process fields for SQL queries.
type ProcessDetail struct {
	PID       uint32   `json:"pid"`
	ParentPID uint32   `json:"parent_pid"`
	UID       uint32   `json:"uid"`
	GID       uint32   `json:"gid"`
	Command   string   `json:"command"`
	Filename  string   `json:"filename"`
	Arguments []string `json:"arguments,omitempty"`
}

// NetworkDetail carries flat network fields for SQL queries.
type NetworkDetail struct {
	SrcIP             string `json:"src_ip"`
	DstIP             string `json:"dst_ip"`
	SrcPort           uint16 `json:"src_port"`
	DstPort           uint16 `json:"dst_port"`
	Protocol          string `json:"protocol"`
	Direction         string `json:"direction"`
	ConnectionState   string `json:"connection_state,omitempty"`
	IngressRestricted bool   `json:"ingress_restricted"`
	EgressRestricted  bool   `json:"egress_restricted"`
}

// FileDetail carries flat file fields for SQL queries.
type FileDetail struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	Mode      uint32 `json:"mode"`
	Sensitive bool   `json:"sensitive"`
}

// DNSDetail carries flat DNS fields for SQL queries.
type DNSDetail struct {
	Query        string `json:"query"`
	QueryType    string `json:"query_type"`
	ResponseCode int    `json:"response_code"`
	QueryAllowed bool   `json:"query_allowed"`
}

// CapabilityDetail carries flat capability fields for SQL queries.
type CapabilityDetail struct {
	Name      string `json:"name"`
	Allowed   bool   `json:"allowed"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	SyscallID uint32 `json:"syscall_id"`
}

// TLSDetail carries flat TLS fields for SQL queries.
type TLSDetail struct {
	JA3Hash    string `json:"ja3_hash"`
	JA3String  string `json:"ja3_string,omitempty"`
	SNI        string `json:"sni,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
	CertIssuer string `json:"cert_issuer,omitempty"`
	CertExpiry int64  `json:"cert_expiry,omitempty"`
}

// EventDetail holds the type-specific flat fields. Only one inner field is non-nil per event.
type EventDetail struct {
	Process    *ProcessDetail    `json:"process_execution,omitempty"`
	Network    *NetworkDetail    `json:"network_connection,omitempty"`
	File       *FileDetail       `json:"file_access,omitempty"`
	DNS        *DNSDetail        `json:"dns_query,omitempty"`
	Capability *CapabilityDetail `json:"capability_usage,omitempty"`
	TLS        *TLSDetail        `json:"tls_client_hello,omitempty"`
}

// ANCHOR: EventMetadata - Feature: rich analytics metadata - Apr 29, 2026
// Consolidates all computed signals (risk score, threat indicators, workload identity,
// security posture, flat event detail) into one top-level field so ClickHouse can index
// every important dimension without joining sparse context fields.
type EventMetadata struct {
	EventID              string               `json:"event_id"`
	Source               string               `json:"source"`
	Severity             string               `json:"severity"`
	RiskScore            int                  `json:"risk_score"`
	ComplianceStatus     string               `json:"compliance_status"`
	ViolationCount       int                  `json:"violation_count"`
	CISControls          []string             `json:"cis_controls,omitempty"`
	SeverityDistribution SeverityDistribution `json:"severity_distribution"`
	ThreatIndicators     []string             `json:"threat_indicators,omitempty"`
	Workload             WorkloadMeta         `json:"workload"`
	SecurityPosture      SecurityPosture      `json:"security_posture"`
	EventDetail          EventDetail          `json:"event_detail"`
}

// -----------------------------------------------------------------------
// WebhookEvent — the record POSTed to the external ingest listener
// -----------------------------------------------------------------------

// WebhookEvent is the per-event record POSTed to the external ingest listener.
// Raw context fields carry the full enriched data; Metadata carries pre-computed
// analytics signals so the ingest program can insert without further processing.
type WebhookEvent struct {
	Type       EventType                     `json:"type"`
	Timestamp  time.Time                     `json:"timestamp"`
	ClusterID  string                        `json:"cluster_id"`
	NodeName   string                        `json:"node_name"`
	Kubernetes *enrichment.K8sContext        `json:"kubernetes,omitempty"`
	Container  *enrichment.ContainerContext  `json:"container,omitempty"`
	Process    *enrichment.ProcessContext    `json:"process,omitempty"`
	Network    *enrichment.NetworkContext    `json:"network,omitempty"`
	DNS        *enrichment.DNSContext        `json:"dns,omitempty"`
	File       *enrichment.FileContext       `json:"file,omitempty"`
	Capability *enrichment.CapabilityContext `json:"capability,omitempty"`
	TLS        *enrichment.TLSContext        `json:"tls,omitempty"`
	Violations []ViolationSummary            `json:"violations,omitempty"`
	Metadata   EventMetadata                 `json:"metadata"`
}

// -----------------------------------------------------------------------
// WebhookPusher
// -----------------------------------------------------------------------

// WebhookPusher batches enriched events and POSTs them to a remote ingest endpoint.
type WebhookPusher struct {
	config    WebhookConfig
	clusterID string
	nodeName  string
	client    *http.Client
	eventCh   chan WebhookEvent
	logger    *zap.Logger
	done      chan struct{}
	wg        sync.WaitGroup
	// ANCHOR: WebhookPusher Start/Stop once guards - Bug #1/#2: double-call panic and duplicate goroutine - Apr 30, 2026
	// close(done) panics on a second call; a second Start() spawns a duplicate flushLoop that races
	// on eventCh and corrupts the WaitGroup counter. sync.Once makes both calls idempotent.
	startOnce sync.Once
	stopOnce  sync.Once
}

// ANCHOR: FlushInterval/Timeout zero-value guards - Bug #3: NewTicker(0) panic - Apr 30, 2026
// BatchSize guard was already present; FlushInterval=0 panics time.NewTicker and Timeout=0
// means no HTTP deadline — flush goroutine can block indefinitely on a slow endpoint.
func NewWebhookPusher(cfg WebhookConfig, clusterID, nodeName string, logger *zap.Logger) *WebhookPusher {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &WebhookPusher{
		config:    cfg,
		clusterID: clusterID,
		nodeName:  nodeName,
		client:    &http.Client{Timeout: cfg.Timeout},
		eventCh:   make(chan WebhookEvent, cfg.BatchSize*4),
		logger:    logger,
		done:      make(chan struct{}),
	}
}

// Start launches the background flush goroutine. Safe to call multiple times; only the first call has effect.
func (p *WebhookPusher) Start(ctx context.Context) {
	p.startOnce.Do(func() {
		p.wg.Add(1)
		go p.flushLoop(ctx)
	})
}

// ANCHOR: Stop drain guarantee - Bug fix: Stop returned before final POST completed - Apr 30, 2026
// Closes done to signal the flush goroutine, then blocks on wg.Wait() until the goroutine
// finishes its drain+flush. Without this, a fast exit could drop the last in-flight batch.
// Safe to call multiple times; only the first call closes done.
func (p *WebhookPusher) Stop() {
	p.stopOnce.Do(func() {
		close(p.done)
	})
	p.wg.Wait()
}

// Send enqueues an enriched event for outbound delivery.
func (p *WebhookPusher) Send(event *enrichment.EnrichedEvent, violations []*rules.Violation) {
	if event == nil {
		return
	}
	we := buildWebhookEvent(event, violations, p.clusterID, p.nodeName)
	select {
	case p.eventCh <- we:
	default:
		p.logger.Warn("webhook pusher channel full, dropping event",
			zap.String("type", string(we.Type)),
		)
	}
}

func (p *WebhookPusher) flushLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.config.FlushInterval)
	defer ticker.Stop()

	batch := make([]WebhookEvent, 0, p.config.BatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := p.post(ctx, batch); err != nil {
			p.logger.Warn("webhook push failed",
				zap.Error(err),
				zap.Int("batch_size", len(batch)),
			)
		}
		batch = batch[:0]
	}

	for {
		select {
		case evt := <-p.eventCh:
			batch = append(batch, evt)
			if len(batch) >= p.config.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-p.done:
			p.drainAndFlush(&batch)
			return
		case <-ctx.Done():
			p.drainAndFlush(&batch)
			return
		}
	}
}

// ANCHOR: drainAndFlush - Bug fix: ctx.Done path dropped in-flight batch - Apr 30, 2026
// Drains any remaining events from the channel into the existing partial batch, then POSTs
// using a fresh context.Background() timeout so the final flush succeeds even when the agent
// context is already cancelled (which is the case on normal SIGTERM shutdown).
// Receives a pointer so callers don't silently lose appended events on capacity growth.
func (p *WebhookPusher) drainAndFlush(batch *[]WebhookEvent) {
draining:
	for {
		select {
		case evt := <-p.eventCh:
			*batch = append(*batch, evt)
		default:
			break draining
		}
	}
	if len(*batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()
	if err := p.post(ctx, *batch); err != nil {
		p.logger.Warn("webhook shutdown flush failed",
			zap.Error(err),
			zap.Int("batch_size", len(*batch)),
		)
	}
}

func (p *WebhookPusher) post(ctx context.Context, batch []WebhookEvent) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	doRequest := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TargetURL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range p.config.Headers {
			req.Header.Set(k, v)
		}
		return p.client.Do(req)
	}

	// ANCHOR: postBatch retry - Bug #6: transient network failures silently dropped entire batch - Apr 30, 2026
	// One immediate retry on network errors only (not 4xx/5xx — those are application-layer
	// rejections that a retry won't fix). Keeps the failure mode explicit and bounded.
	resp, err := doRequest()
	if err != nil {
		var netErr interface{ Timeout() bool }
		if errors.As(err, &netErr) || isNetworkError(err) {
			p.logger.Debug("webhook post transient error, retrying once", zap.Error(err))
			resp, err = doRequest()
		}
		if err != nil {
			return fmt.Errorf("http post: %w", err)
		}
	}

	// ANCHOR: postBatch body drain - Bug #5: unread error body blocked HTTP connection reuse - Apr 30, 2026
	// net/http only reuses a connection when the response body is fully consumed before Close().
	// Skipping the drain on error responses causes a new TCP connection per failed batch.
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck // draining for connection reuse; content is discarded

	if resp.StatusCode >= 400 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, p.config.TargetURL)
	}
	p.logger.Debug("webhook batch pushed",
		zap.Int("events", len(batch)),
		zap.Int("status", resp.StatusCode),
	)
	return nil
}

// ANCHOR: redactHeaders - Bug #7: auth tokens could leak into logs via header map - Apr 30, 2026
// Returns a copy of the header map with values for sensitive keys replaced by "[redacted]".
// Used only in log/error paths — the actual request always receives the original values.
func redactHeaders(headers map[string]string) map[string]string {
	sensitiveKeys := map[string]bool{
		"authorization": true,
		"x-api-key":     true,
		"x-auth-token":  true,
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if sensitiveKeys[strings.ToLower(k)] {
			out[k] = "[redacted]"
		} else {
			out[k] = v
		}
	}
	return out
}

// isNetworkError reports whether err looks like a transient network-layer failure
// (connection refused, reset, EOF) as opposed to a DNS or TLS error where retrying immediately
// is unlikely to help.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "EOF")
}

// -----------------------------------------------------------------------
// Event construction
// -----------------------------------------------------------------------

func buildWebhookEvent(event *enrichment.EnrichedEvent, violations []*rules.Violation, clusterID, nodeName string) WebhookEvent {
	var summaries []ViolationSummary
	if len(violations) > 0 {
		summaries = make([]ViolationSummary, 0, len(violations))
		for _, v := range violations {
			if v == nil {
				continue
			}
			summaries = append(summaries, ViolationSummary{
				ControlID:      v.ControlID,
				Title:          v.Title,
				Severity:       v.Severity,
				Description:    v.Description,
				RemediationRef: v.RemediationRef,
			})
		}
	}

	return WebhookEvent{
		Type:       eventTypeName(event.EventType),
		Timestamp:  event.Timestamp,
		ClusterID:  clusterID,
		NodeName:   nodeName,
		Kubernetes: event.Kubernetes,
		Container:  event.Container,
		Process:    event.Process,
		Network:    event.Network,
		DNS:        event.DNS,
		File:       event.File,
		Capability: event.Capability,
		TLS:        event.TLS,
		Violations: summaries,
		Metadata:   buildMetadata(event, violations, summaries),
	}
}

// eventTypeName normalises the raw event type string to the canonical EventType constant.
func eventTypeName(raw string) EventType {
	switch strings.ToLower(raw) {
	case "process", "process_execution":
		return EventTypeProcess
	case "network", "network_connection":
		return EventTypeNetwork
	case "dns", "dns_query":
		return EventTypeDNS
	case "file", "file_access":
		return EventTypeFile
	case "capability", "capability_usage":
		return EventTypeCapability
	case "tls", "tls_client_hello":
		return EventTypeTLS
	default:
		return EventType(raw)
	}
}

// -----------------------------------------------------------------------
// Metadata computation
// -----------------------------------------------------------------------

// ANCHOR: buildMetadata - Feature: rich analytics metadata - Apr 29, 2026
// Pre-computes all analytics signals so the ClickHouse ingest program receives
// ready-to-insert columns without needing to re-parse the raw context fields.
func buildMetadata(
	event *enrichment.EnrichedEvent,
	violations []*rules.Violation,
	summaries []ViolationSummary,
) EventMetadata {
	m := EventMetadata{
		EventID: newEventID(),
		Source:  "ebpf",
	}

	// --- violations ---
	m.ViolationCount = len(summaries)
	if m.ViolationCount > 0 {
		m.ComplianceStatus = "violation"
	} else {
		m.ComplianceStatus = "clean"
	}

	dist := SeverityDistribution{}
	seen := map[string]bool{}
	for _, v := range summaries {
		if !seen[v.ControlID] {
			seen[v.ControlID] = true
			m.CISControls = append(m.CISControls, v.ControlID)
		}
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			dist.Critical++
		case "HIGH":
			dist.High++
		case "MEDIUM":
			dist.Medium++
		case "LOW":
			dist.Low++
		}
	}
	m.SeverityDistribution = dist

	// risk score: CRITICAL=25, HIGH=20, MEDIUM=10, LOW=5, capped at 100
	score := dist.Critical*25 + dist.High*20 + dist.Medium*10 + dist.Low*5
	if score > 100 {
		score = 100
	}
	m.RiskScore = score

	// highest severity
	switch {
	case dist.Critical > 0:
		m.Severity = "CRITICAL"
	case dist.High > 0:
		m.Severity = "HIGH"
	case dist.Medium > 0:
		m.Severity = "MEDIUM"
	case dist.Low > 0:
		m.Severity = "LOW"
	default:
		m.Severity = event.Severity
		if m.Severity == "" {
			m.Severity = "INFO"
		}
	}

	// --- workload ---
	m.Workload = buildWorkload(event)

	// --- security posture ---
	m.SecurityPosture = buildSecurityPosture(event)

	// --- threat indicators ---
	m.ThreatIndicators = buildThreatIndicators(event)

	// --- event detail ---
	m.EventDetail = buildEventDetail(event)

	return m
}

func buildWorkload(event *enrichment.EnrichedEvent) WorkloadMeta {
	w := WorkloadMeta{}
	if k := event.Kubernetes; k != nil {
		w.Namespace = k.Namespace
		w.PodName = k.PodName
		w.PodUID = k.PodUID
		w.ServiceAccount = k.ServiceAccount
		w.Image = k.Image
		w.ImageRegistry = k.ImageRegistry
		w.ImageTag = k.ImageTag
		if k.OwnerRef != nil {
			w.OwnerKind = k.OwnerRef.Kind
			w.OwnerName = k.OwnerRef.Name
		}
	}
	if c := event.Container; c != nil {
		w.ContainerName = c.ContainerName
		w.ContainerID = c.ContainerID
	}
	return w
}

func buildSecurityPosture(event *enrichment.EnrichedEvent) SecurityPosture {
	p := SecurityPosture{}
	if k := event.Kubernetes; k != nil {
		p.RBACLevel = k.RBACLevel
		p.RBACEnforced = k.RBACEnforced
		p.AutomountServiceAccountToken = k.AutomountServiceAccountToken
		p.HasNetworkPolicy = k.HasDefaultDenyNetworkPolicy
		p.ServiceAccountPermissions = k.ServiceAccountPermissions
	}
	if c := event.Container; c != nil {
		p.Privileged = c.Privileged
		p.RunAsRoot = c.RunAsRoot
		p.AllowPrivilegeEscalation = c.AllowPrivilegeEscalation
		p.HostNetwork = c.HostNetwork
		p.HostPID = c.HostPID
		p.HostIPC = c.HostIPC
		p.ReadOnlyFilesystem = c.ReadOnlyFilesystem
		p.KernelHardening = c.KernelHardening
		p.SeccompProfile = c.SeccompProfile
		p.ApparmorProfile = c.ApparmorProfile
		p.ImageSigned = c.ImageSigned
		p.ImageScanStatus = c.ImageScanStatus
	}
	return p
}

var dangerousCapabilities = map[string]bool{
	"CAP_SYS_ADMIN":   true,
	"CAP_NET_ADMIN":   true,
	"CAP_NET_RAW":     true,
	"CAP_SYS_PTRACE":  true,
	"CAP_SYS_MODULE":  true,
	"CAP_DAC_OVERRIDE": true,
	"CAP_SETUID":      true,
	"CAP_SETGID":      true,
}

func buildThreatIndicators(event *enrichment.EnrichedEvent) []string {
	var indicators []string

	add := func(s string) { indicators = append(indicators, s) }

	// "root_process" may be added up to three times (Process, File, Capability UID fields)
	// and is deduplicated by the dedupStrings call at the end of this function.
	if event.Process != nil && event.Process.UID == 0 {
		add("root_process")
	}
	if event.File != nil && event.File.UID == 0 {
		add("root_process")
	}
	if event.Capability != nil && event.Capability.UID == 0 {
		add("root_process")
	}

	// container security flags
	if c := event.Container; c != nil {
		if c.Privileged {
			add("privileged_container")
		}
		if c.AllowPrivilegeEscalation {
			add("allow_privilege_escalation")
		}
		if c.HostNetwork || c.HostPID || c.HostIPC {
			add("host_namespace_escape")
		}
		if c.MemoryLimit == "" && c.CPULimit == "" {
			add("missing_resource_limits")
		}
		if c.SeccompProfile == "" || strings.EqualFold(c.SeccompProfile, "Unconfined") {
			add("no_seccomp")
		}
		if c.ApparmorProfile == "" {
			add("no_apparmor")
		}
		if !c.ImageSigned {
			add("unsigned_image")
		}
		if c.ImageScanStatus != "" && !strings.EqualFold(c.ImageScanStatus, "scanned") {
			add("unscanned_image")
		}
	}

	// K8s-level signals
	if k := event.Kubernetes; k != nil {
		if k.RBACLevel >= 2 {
			add("excess_rbac_permissions")
		}
		if k.ServiceAccountTokenAge > 7_776_000 { // 90 days in seconds
			add("stale_sa_token")
		}
		if !k.HasDefaultDenyNetworkPolicy {
			add("no_network_policy")
		}
		if k.AutomountServiceAccountToken {
			add("automount_sa_token")
		}
	}

	// event-specific signals
	if event.File != nil && event.File.Sensitive {
		add("sensitive_file_access")
	}
	if event.Capability != nil && dangerousCapabilities[event.Capability.Name] {
		add("dangerous_capability")
	}

	// deduplicate (root_process may be added twice for mixed events)
	return dedupStrings(indicators)
}

func buildEventDetail(event *enrichment.EnrichedEvent) EventDetail {
	d := EventDetail{}

	if p := event.Process; p != nil {
		d.Process = &ProcessDetail{
			PID:       p.PID,
			ParentPID: p.ParentPID,
			UID:       p.UID,
			GID:       p.GID,
			Command:   p.Command,
			Filename:  p.Filename,
			Arguments: p.Arguments,
		}
	}
	if n := event.Network; n != nil {
		d.Network = &NetworkDetail{
			SrcIP:             n.SourceIP,
			DstIP:             n.DestinationIP,
			SrcPort:           n.SourcePort,
			DstPort:           n.DestinationPort,
			Protocol:          n.Protocol,
			Direction:         n.Direction,
			ConnectionState:   n.ConnectionState,
			IngressRestricted: n.IngressRestricted,
			EgressRestricted:  n.EgressRestricted,
		}
	}
	if f := event.File; f != nil {
		d.File = &FileDetail{
			Path:      f.Path,
			Operation: f.Operation,
			PID:       f.PID,
			UID:       f.UID,
			Mode:      f.Mode,
			Sensitive: f.Sensitive,
		}
	}
	if dns := event.DNS; dns != nil {
		d.DNS = &DNSDetail{
			Query:        dns.QueryName,
			QueryType:    dns.QueryType,
			ResponseCode: dns.ResponseCode,
			QueryAllowed: dns.QueryAllowed,
		}
	}
	if cap := event.Capability; cap != nil {
		d.Capability = &CapabilityDetail{
			Name:      cap.Name,
			Allowed:   cap.Allowed,
			PID:       cap.PID,
			UID:       cap.UID,
			SyscallID: cap.SyscallID,
		}
	}
	if tls := event.TLS; tls != nil {
		d.TLS = &TLSDetail{
			JA3Hash:    tls.JA3Fingerprint,
			JA3String:  tls.JA3String,
			SNI:        tls.SNI,
			TLSVersion: tls.TLSVersion,
			CertSHA256: tls.CertSHA256,
			CertIssuer: tls.CertIssuer,
			CertExpiry: tls.CertExpiry,
		}
	}

	return d
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

func newEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// format as UUID v4
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:])
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
