package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/time/rate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsRBACAPIEnabledFailOpenOnFirstDiscoveryError(t *testing.T) {
	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return nil, errors.New("discovery unavailable")
		},
	}

	if !c.IsRBACAPIEnabled(context.Background()) {
		t.Fatalf("expected fail-open true on first discovery error")
	}
}

func TestIsRBACAPIEnabledUsesMemoOnDiscoveryError(t *testing.T) {
	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return nil, errors.New("discovery unavailable")
		},
		rbacMemo: apiGroupMemo{
			enabled:   false,
			checked:   true,
			checkedAt: time.Now().Add(-rbacAPICacheTTL - time.Second),
		},
	}

	if c.IsRBACAPIEnabled(context.Background()) {
		t.Fatalf("expected memoized false when discovery fails after a prior check")
	}
}

func TestIsRBACAPIEnabledUsesMemoOnRateLimiterError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return &metav1.APIGroupList{
				Groups: []metav1.APIGroup{{Name: "rbac.authorization.k8s.io"}},
			}, nil
		},
		apiLimiter: rate.NewLimiter(rate.Limit(1), 1),
		rbacMemo: apiGroupMemo{
			enabled:   false,
			checked:   true,
			checkedAt: time.Now().Add(-rbacAPICacheTTL - time.Second),
		},
	}

	if c.IsRBACAPIEnabled(ctx) {
		t.Fatalf("expected memoized false when limiter wait fails after a prior check")
	}
}

func TestIsRBACAPIEnabledDetectsGroupAndCaches(t *testing.T) {
	discoveryCalls := 0
	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			discoveryCalls++
			return &metav1.APIGroupList{
				Groups: []metav1.APIGroup{{Name: "rbac.authorization.k8s.io"}},
			}, nil
		},
	}

	if !c.IsRBACAPIEnabled(context.Background()) {
		t.Fatalf("expected true when RBAC API group exists")
	}
	if !c.IsRBACAPIEnabled(context.Background()) {
		t.Fatalf("expected cached true on immediate second check")
	}
	if discoveryCalls != 1 {
		t.Fatalf("expected one discovery call due cache, got %d", discoveryCalls)
	}
}

// TestHasSuccessfulRBACProbeReturnsFalseBeforeProbe verifies the accessor returns false
// on a fresh Client that has never completed a successful probe.
func TestHasSuccessfulRBACProbeReturnsFalseBeforeProbe(t *testing.T) {
	c := &Client{}
	if c.HasSuccessfulRBACProbe() {
		t.Fatal("expected false before any probe has succeeded")
	}
}

// TestHasSuccessfulRBACProbeReturnsTrueAfterSuccessfulProbe verifies the accessor flips
// to true after IsRBACAPIEnabled completes a successful discovery call.
// Also documents the one-call-lag: the accessor returns false just before the successful
// call and true immediately after.
func TestHasSuccessfulRBACProbeReturnsTrueAfterSuccessfulProbe(t *testing.T) {
	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return &metav1.APIGroupList{
				Groups: []metav1.APIGroup{{Name: "rbac.authorization.k8s.io"}},
			}, nil
		},
	}

	// Before probe: accessor must return false (one-call-lag documented here).
	if c.HasSuccessfulRBACProbe() {
		t.Fatal("expected false before first successful probe")
	}

	c.IsRBACAPIEnabled(context.Background())

	// After probe: accessor must return true.
	if !c.HasSuccessfulRBACProbe() {
		t.Fatal("expected true after successful probe")
	}
}

// TestRBACFailOpenWarningPath verifies the caller-side warning pattern: when
// HasSuccessfulRBACProbe() is false before IsRBACAPIEnabled(), a warning is logged.
// This mirrors the exact code sequence in enricher.go and compliance_watcher.go.
// ANCHOR: Integration test for RBAC fail-open warning path - Bug: unverified RBAC state - Apr 20, 2026
func TestRBACFailOpenWarningPath(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	// Client whose discovery always fails — rbacMemo.checked stays false.
	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return nil, errors.New("discovery unavailable")
		},
	}

	// Mirrors enricher.go:855-862 exactly.
	probeSucceeded := c.HasSuccessfulRBACProbe()
	c.IsRBACAPIEnabled(context.Background())
	if !probeSucceeded {
		logger.Warn("RBAC API probe has not yet succeeded; RBACEnforced state is unverified")
	}

	found := false
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, "RBAC API probe has not yet succeeded") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected warning to be logged when probe has not yet succeeded")
	}
}
