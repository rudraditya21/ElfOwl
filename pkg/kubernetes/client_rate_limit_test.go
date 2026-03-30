package kubernetes

import (
	"context"
	"os"
	"testing"
)

func TestLoadK8sAPIRateLimit(t *testing.T) {
	t.Setenv("OWL_K8S_API_RATE_LIMIT", "75.5")
	if got := loadK8sAPIRateLimit(); got != 75.5 {
		t.Fatalf("expected parsed rate limit 75.5, got %v", got)
	}

	t.Setenv("OWL_K8S_API_RATE_LIMIT", "invalid")
	if got := loadK8sAPIRateLimit(); got != defaultK8sAPIRateLimit {
		t.Fatalf("expected default rate limit %v on invalid value, got %v", defaultK8sAPIRateLimit, got)
	}
}

func TestLoadK8sAPIBurst(t *testing.T) {
	t.Setenv("OWL_K8S_API_BURST", "120")
	if got := loadK8sAPIBurst(); got != 120 {
		t.Fatalf("expected parsed burst 120, got %d", got)
	}

	t.Setenv("OWL_K8S_API_BURST", "invalid")
	if got := loadK8sAPIBurst(); got != defaultK8sAPIBurst {
		t.Fatalf("expected default burst %d on invalid value, got %d", defaultK8sAPIBurst, got)
	}
}

func TestWaitForAPIBudgetWithoutLimiter(t *testing.T) {
	c := &Client{}
	if err := c.waitForAPIBudget(context.Background()); err != nil {
		t.Fatalf("expected nil wait error without limiter, got %v", err)
	}
}

func TestLoadK8sAPIRateLimitUsesDefaultWhenUnset(t *testing.T) {
	if err := os.Unsetenv("OWL_K8S_API_RATE_LIMIT"); err != nil {
		t.Fatalf("failed to unset env: %v", err)
	}
	if got := loadK8sAPIRateLimit(); got != defaultK8sAPIRateLimit {
		t.Fatalf("expected default when env unset, got %v", got)
	}
}
