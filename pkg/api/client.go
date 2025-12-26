// ANCHOR: Owl SaaS push-only API client - Dec 26, 2025
// Pushes signed/encrypted evidence to Owl SaaS (one-way outbound only)
// IMPLEMENTATION IN PROGRESS - Week 3 task

package api

import (
	"context"
	"fmt"
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

// Push sends buffered events to Owl SaaS (single attempt)
func (c *Client) Push(ctx context.Context, bufferedEvents []*evidence.BufferedEvent) error {
	// TODO: Week 3 implementation
	// 1. Convert buffered events to signed/encrypted format
	// 2. Build push batch
	// 3. Compress with gzip
	// 4. Send to Owl SaaS
	// 5. Handle response

	if len(bufferedEvents) == 0 {
		return nil
	}

	c.logger.Debug("push: processing events",
		zap.Int("count", len(bufferedEvents)),
	)

	return fmt.Errorf("not yet implemented")
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
