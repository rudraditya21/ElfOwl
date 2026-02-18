// ANCHOR: Owl SaaS push-only API client - Dec 26, 2025
// Pushes signed/encrypted evidence to Owl SaaS (one-way outbound only)
// IMPLEMENTATION IN PROGRESS - Week 3 task

package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/config"
	"github.com/udyansh/elf-owl/pkg/evidence"
)

// Client provides push-only communication with Owl SaaS
// INVARIANT: This client can ONLY push evidence, never receives commands
type Client struct {
	endpoint      string
	clusterID     string
	nodeName      string
	jwtToken      string
	httpClient    *resty.Client
	logger        *zap.Logger
	signer        *evidence.Signer
	cipher        *evidence.Cipher
	retryConfig   config.RetryConfig

	// Metrics (thread-safe with mutex)
	mu              sync.Mutex
	lastPushTime    time.Time
	failureCount    int64
	successCount    int64
}

// NewClient creates a new Owl API client
func NewClient(
	endpoint string,
	clusterID string,
	nodeName string,
	jwtToken string,
	signer *evidence.Signer,
	cipher *evidence.Cipher,
	retryConfig config.RetryConfig,
) (*Client, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	if clusterID == "" {
		return nil, fmt.Errorf("cluster_id is required")
	}

	if nodeName == "" {
		return nil, fmt.Errorf("node_name is required")
	}

	logger, _ := zap.NewProduction()

	return &Client{
		endpoint:    endpoint,
		clusterID:   clusterID,
		nodeName:    nodeName,
		jwtToken:    jwtToken,
		httpClient:  resty.New(),
		logger:      logger,
		signer:      signer,
		cipher:      cipher,
		retryConfig: retryConfig,
	}, nil
}

// PushBatch is the JSON payload sent to the Owl SaaS events endpoint.
type PushBatch struct {
	ClusterID string                   `json:"cluster_id"`
	NodeName  string                   `json:"node_name"`
	Events    []*evidence.BufferedEvent `json:"events"`
	Signature string                   `json:"signature"`
	SentAt    time.Time                `json:"sent_at"`
}

// Push sends buffered events to Owl SaaS (single attempt).
//
// ANCHOR: Implement event push: JSON+sign+gzip+HTTP POST - Feb 18, 2026
// WHY: Previously returned "not yet implemented"; events were buffered locally
//      but never shipped to the Owl compliance platform.
// WHAT: Serialise the batch to JSON, sign it with HMAC-SHA256 for integrity,
//       gzip-compress the payload to reduce bandwidth, then POST to the Owl
//       /api/v1/evidence endpoint with JWT Bearer auth and cluster identity headers.
// HOW:  1. json.Marshal the PushBatch (events + cluster metadata)
//       2. Sign the raw JSON bytes with c.signer.Sign() → HMAC-SHA256 hex
//       3. Embed signature in a wrapper, re-marshal, gzip compress
//       4. POST with Authorization, Content-Encoding, X-Cluster-ID headers
//       5. Accept HTTP 200/202; anything else is an error
func (c *Client) Push(ctx context.Context, bufferedEvents []*evidence.BufferedEvent) error {
	if len(bufferedEvents) == 0 {
		return nil
	}

	c.logger.Debug("push: serialising events",
		zap.Int("count", len(bufferedEvents)),
	)

	// Step 1: Build batch payload
	batch := &PushBatch{
		ClusterID: c.clusterID,
		NodeName:  c.nodeName,
		Events:    bufferedEvents,
		SentAt:    time.Now().UTC(),
	}

	// Step 2: Marshal to JSON
	rawJSON, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("push: marshal batch: %w", err)
	}

	// Step 3: Sign the raw JSON for integrity verification by Owl SaaS
	if c.signer != nil {
		batch.Signature = c.signer.Sign(rawJSON)
		// Re-marshal with signature included
		rawJSON, err = json.Marshal(batch)
		if err != nil {
			return fmt.Errorf("push: marshal signed batch: %w", err)
		}
	}

	// Step 4: gzip compress
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(rawJSON); err != nil {
		return fmt.Errorf("push: gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("push: gzip close: %w", err)
	}

	// Step 5: POST to Owl SaaS
	url := c.endpoint + "/api/v1/evidence"
	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Content-Encoding", "gzip").
		SetHeader("Authorization", "Bearer "+c.jwtToken).
		SetHeader("X-Cluster-ID", c.clusterID).
		SetHeader("X-Node-Name", c.nodeName).
		SetBody(buf.Bytes()).
		Post(url)

	if err != nil {
		return fmt.Errorf("push: http post: %w", err)
	}

	if resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusAccepted {
		return fmt.Errorf("push: unexpected status %d: %s", resp.StatusCode(), resp.String())
	}

	c.logger.Debug("push: succeeded",
		zap.Int("events", len(bufferedEvents)),
		zap.Int("compressedBytes", buf.Len()),
		zap.Int("statusCode", resp.StatusCode()),
	)

	return nil
}

// PushWithRetry sends events with exponential backoff retry
func (c *Client) PushWithRetry(ctx context.Context, bufferedEvents []*evidence.BufferedEvent) error {
	if len(bufferedEvents) == 0 {
		return nil
	}

	backoff := c.retryConfig.InitialBackoff

	for attempt := 0; attempt < c.retryConfig.MaxRetries; attempt++ {
		err := c.Push(ctx, bufferedEvents)
		if err == nil {
			// ANCHOR: Update metrics on successful push with mutex protection - Dec 26, 2025
			// Use mutex to safely update lastPushTime and successCount
			c.mu.Lock()
			c.lastPushTime = time.Now()
			c.successCount++
			c.mu.Unlock()
			return nil
		}

		if attempt < c.retryConfig.MaxRetries-1 {
			c.logger.Warn("push attempt failed, retrying",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
				zap.Error(err),
			)

			select {
			case <-time.After(backoff):
				// Calculate next backoff
				backoff = time.Duration(float64(backoff) * c.retryConfig.BackoffMultiplier)
				if backoff > c.retryConfig.MaxBackoff {
					backoff = c.retryConfig.MaxBackoff
				}

			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	// ANCHOR: Increment failure count with mutex protection - Dec 26, 2025
	// Thread-safe update of failure counter
	c.mu.Lock()
	c.failureCount++
	c.mu.Unlock()
	return fmt.Errorf("push failed after %d attempts", c.retryConfig.MaxRetries)
}

// LastPushTime returns the time of last successful push
func (c *Client) LastPushTime() time.Time {
	// ANCHOR: Thread-safe read of lastPushTime with mutex - Dec 26, 2025
	// Protect time.Time field access with mutex instead of unsafe atomic operations
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPushTime
}

// SuccessCount returns the total number of successful pushes
func (c *Client) SuccessCount() int64 {
	// ANCHOR: Thread-safe read of successCount with mutex - Dec 26, 2025
	// Protect counter access with mutex for consistency
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.successCount
}

// FailureCount returns the total number of failed pushes
func (c *Client) FailureCount() int64 {
	// ANCHOR: Thread-safe read of failureCount with mutex - Dec 26, 2025
	// Protect counter access with mutex for consistency
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failureCount
}
