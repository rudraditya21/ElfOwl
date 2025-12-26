// ANCHOR: Shared configuration types - Dec 26, 2025
// Types shared between multiple packages to avoid circular imports

package config

import "time"

// RetryConfig defines retry settings for API operations
type RetryConfig struct {
	MaxRetries        int
	InitialBackoff    time.Duration
	MaxBackoff        time.Duration
	BackoffMultiplier float64
}
