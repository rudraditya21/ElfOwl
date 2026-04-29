// ANCHOR: Outbound webhook pusher - Feature: ClickHouse event push - Apr 29, 2026
// Batches all enriched events from every eBPF monitor and POSTs them as a JSON array
// to a configured target_url so an external ingest program can store them in ClickHouse.
// Replaces the previous inbound ingestion endpoint.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/rules"
)

// EventType identifies the kind of security event in a WebhookEvent payload.
type EventType string

const (
	EventTypeProcess    EventType = "process"
	EventTypeNetwork    EventType = "network"
	EventTypeDNS        EventType = "dns"
	EventTypeFile       EventType = "file"
	EventTypeCapability EventType = "capability"
	EventTypeTLS        EventType = "tls"
)

// ViolationSummary is a compact violation record embedded in the webhook payload.
type ViolationSummary struct {
	ControlID      string `json:"control_id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Description    string `json:"description,omitempty"`
	RemediationRef string `json:"remediation_ref,omitempty"`
}

// WebhookEvent is the per-event record POSTed to the external ingest listener.
// Only the context fields relevant to the event type are non-nil.
// The external program receives a JSON array of these records per batch.
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
}

// WebhookPusher batches enriched events and POSTs them to a remote ingest endpoint.
// It is safe for concurrent use via the internal channel.
type WebhookPusher struct {
	config    WebhookConfig
	clusterID string
	nodeName  string
	client    *http.Client
	eventCh   chan WebhookEvent
	logger    *zap.Logger
	done      chan struct{}
}

// NewWebhookPusher creates a WebhookPusher from the agent config.
func NewWebhookPusher(cfg WebhookConfig, clusterID, nodeName string, logger *zap.Logger) *WebhookPusher {
	return &WebhookPusher{
		config:    cfg,
		clusterID: clusterID,
		nodeName:  nodeName,
		client:    &http.Client{Timeout: cfg.Timeout},
		// Channel sized to 4× batch capacity to absorb bursts without dropping.
		eventCh: make(chan WebhookEvent, cfg.BatchSize*4),
		logger:  logger,
		done:    make(chan struct{}),
	}
}

// Start launches the background flush goroutine.
func (p *WebhookPusher) Start(ctx context.Context) {
	go p.flushLoop(ctx)
}

// Stop signals the flush goroutine to drain remaining events and exit.
func (p *WebhookPusher) Stop() {
	close(p.done)
}

// Send enqueues an enriched event for outbound delivery. Non-blocking; events are
// logged and dropped when the internal channel is full.
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

// flushLoop accumulates events and posts batches to TargetURL on timer or batch-size trigger.
func (p *WebhookPusher) flushLoop(ctx context.Context) {
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
			// Drain any events queued before Stop() was called.
		draining:
			for {
				select {
				case evt := <-p.eventCh:
					batch = append(batch, evt)
				default:
					break draining
				}
			}
			flush()
			return

		case <-ctx.Done():
			return
		}
	}
}

// post marshals the batch as a JSON array and POSTs it to the configured TargetURL.
func (p *WebhookPusher) post(ctx context.Context, batch []WebhookEvent) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TargetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, p.config.TargetURL)
	}

	p.logger.Debug("webhook batch pushed",
		zap.Int("events", len(batch)),
		zap.Int("status", resp.StatusCode),
	)
	return nil
}

// buildWebhookEvent constructs a WebhookEvent from an enriched event and its violations.
func buildWebhookEvent(event *enrichment.EnrichedEvent, violations []*rules.Violation, clusterID, nodeName string) WebhookEvent {
	we := WebhookEvent{
		Type:       EventType(event.EventType),
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
	}

	if len(violations) > 0 {
		we.Violations = make([]ViolationSummary, 0, len(violations))
		for _, v := range violations {
			if v == nil {
				continue
			}
			we.Violations = append(we.Violations, ViolationSummary{
				ControlID:      v.ControlID,
				Title:          v.Title,
				Severity:       v.Severity,
				Description:    v.Description,
				RemediationRef: v.RemediationRef,
			})
		}
	}

	return we
}
