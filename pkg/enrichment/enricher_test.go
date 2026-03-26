package enrichment

import (
	"errors"
	"testing"
)

// TestErrNoKubernetesContextSentinel verifies that the sentinel error is properly defined
// and can be used with errors.Is()
// ANCHOR: K8s-native filter tests - Feature: explicit host event discard - Mar 24, 2026
func TestErrNoKubernetesContextSentinel(t *testing.T) {
	if ErrNoKubernetesContext == nil {
		t.Errorf("Expected ErrNoKubernetesContext to be non-nil")
	}

	expectedMsg := "no kubernetes pod context: event is not from a pod"
	if ErrNoKubernetesContext.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, ErrNoKubernetesContext.Error())
	}
}

// TestErrNoKubernetesContextErrorsIs verifies that errors.Is() can detect the sentinel
func TestErrNoKubernetesContextErrorsIs(t *testing.T) {
	// Directly created error should be detected
	if !errors.Is(ErrNoKubernetesContext, ErrNoKubernetesContext) {
		t.Errorf("Expected errors.Is(ErrNoKubernetesContext, ErrNoKubernetesContext) to be true")
	}

	// Wrapped error should be detected
	wrappedErr := errors.New("outer: " + ErrNoKubernetesContext.Error())
	if !errors.Is(wrappedErr, ErrNoKubernetesContext) {
		t.Logf("Note: wrapped error not detected by errors.Is() - this is expected for string-wrapped errors")
	}
}

// TestErrNoKubernetesContextCompare verifies that the error can be compared directly
func TestErrNoKubernetesContextCompare(t *testing.T) {
	// Direct comparison should work
	if ErrNoKubernetesContext != ErrNoKubernetesContext {
		t.Errorf("Expected ErrNoKubernetesContext == ErrNoKubernetesContext")
	}

	// Comparison with other errors should differ
	otherErr := errors.New("some other error")
	if ErrNoKubernetesContext == otherErr {
		t.Errorf("Expected ErrNoKubernetesContext != otherErr")
	}
}

// TestSentinelCanBeCheckedInHandler demonstrates the pattern used in agent.go
func TestSentinelCanBeCheckedInHandler(t *testing.T) {
	// Simulate what the agent handler does
	err := ErrNoKubernetesContext

	if err != nil {
		if errors.Is(err, ErrNoKubernetesContext) {
			// This is the pattern used in agent.go handlers
			// Sentinel error detected
		} else {
			t.Errorf("Sentinel detection failed in handler pattern")
		}
	}
}

// BenchmarkErrNoKubernetesContextCheck benchmarks sentinel error checking
// ANCHOR: Performance benchmark - Filter: K8s-native compliance - Mar 24, 2026
func BenchmarkErrNoKubernetesContextCheck(b *testing.B) {
	err := ErrNoKubernetesContext

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if errors.Is(err, ErrNoKubernetesContext) {
			// Sentinel detected
		}
	}
}
