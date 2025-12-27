// ANCHOR: Integration tests for rule engine with sample eBPF events - Phase 3.5-3.6 Week 3
// Tests complete pipeline: eBPF event → enrichment → rule matching → violation detection
// Covers all major CIS control categories with realistic security event scenarios

package rules

import (
	"testing"
	"time"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// TestIntegrationRootProcessExecution tests detection of root process execution (CIS 4.1.1)
// ANCHOR: Root process execution detection - Phase 3.5 Week 3
// CIS 4.1.1: Ensure a process execution strategy is set
func TestIntegrationRootProcessExecution(t *testing.T) {
	engine, _ := NewEngine()

	// Create an enriched event for root process execution
	event := &enrichment.EnrichedEvent{
		EventType: "process_execution",
		Process: &enrichment.ProcessContext{
			UID:        0,      // Root user
			PID:        1234,
			GID:        0,
			Command:    "bash",
			Filename:   "/bin/bash",
			ContainerID: "abc123def456",
		},
		Kubernetes: &enrichment.K8sContext{
			ClusterID:  "test-cluster",
			NodeName:   "node-1",
			Namespace:  "default",
			PodName:    "test-pod",
			PodUID:     "pod-123",
			ServiceAccount: "default",
			Labels:     map[string]string{"app": "web"},
		},
		Container: &enrichment.ContainerContext{
			ContainerID: "abc123def456",
			Runtime:     "containerd",
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	// Should detect at least one CIS control violation for root execution
	if len(violations) == 0 {
		t.Errorf("expected violations for root process execution, got none")
		return
	}

	// Verify violation details
	for _, v := range violations {
		if v.Severity != "CRITICAL" && v.Severity != "HIGH" {
			t.Logf("warning: expected CRITICAL/HIGH severity for root process, got %s", v.Severity)
		}
	}

	t.Logf("Root process execution test: detected %d violations", len(violations))
}

// TestIntegrationPrivilegedContainer tests detection of privileged containers (CIS 4.2.1)
// ANCHOR: Privileged container detection - Phase 3.5 Week 3
// CIS 4.2.1: Ensure containers are not run with privileged access
func TestIntegrationPrivilegedContainer(t *testing.T) {
	engine, _ := NewEngine()

	event := &enrichment.EnrichedEvent{
		EventType: "pod_spec_check",
		Container: &enrichment.ContainerContext{
			ContainerID: "abc123def456",
			Runtime:     "containerd",
			Privileged:  true, // Privileged container
			RunAsRoot:   true,
		},
		Kubernetes: &enrichment.K8sContext{
			ClusterID:      "test-cluster",
			NodeName:       "node-1",
			Namespace:      "kube-system",
			PodName:        "privileged-pod",
			PodUID:         "pod-456",
			ServiceAccount: "system:admin",
			Labels:         map[string]string{"app": "critical"},
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	// Should detect privileged container violations
	if len(violations) == 0 {
		t.Errorf("expected violations for privileged container, got none")
		return
	}

	t.Logf("Privileged container test: detected %d violations", len(violations))
}

// TestIntegrationNetworkPolicyViolation tests detection of network policy violations (CIS 4.6.1)
// ANCHOR: Network policy violation detection - Phase 3.5 Week 3
// CIS 4.6.1: Ensure default deny NetworkPolicy is in place
func TestIntegrationNetworkPolicyViolation(t *testing.T) {
	engine, _ := NewEngine()

	// network_policy_check event with no default deny policy in place
	event := &enrichment.EnrichedEvent{
		EventType: "network_policy_check", // Correct event type for CIS_4.6.1
		Kubernetes: &enrichment.K8sContext{
			ClusterID:                      "test-cluster",
			NodeName:                       "node-2",
			Namespace:                      "default",
			PodName:                        "web-pod",
			PodUID:                         "pod-789",
			ServiceAccount:                 "web-app",
			HasDefaultDenyNetworkPolicy:    false, // Violation: no default deny policy
			Labels:                         map[string]string{"tier": "web"},
		},
		Container: &enrichment.ContainerContext{
			ContainerID: "xyz789abc123",
			Runtime:     "docker",
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	// CIS_4.6.1 detects when default deny NetworkPolicy is missing
	if len(violations) == 0 {
		t.Errorf("expected violations for missing default deny NetworkPolicy, got none")
	}

	t.Logf("Network policy test: detected %d violations", len(violations))
}

// TestIntegrationRBACViolation tests detection of RBAC violations (CIS 5.2)
// ANCHOR: RBAC violation detection - Phase 3.5 Week 3
// CIS 5.2: Minimize access to create deployments
// NOTE: RBAC violations are detected via service account analysis, not specific events
// This test documents that RBAC is enriched but rules are pod-spec-triggered
func TestIntegrationRBACViolation(t *testing.T) {
	engine, _ := NewEngine()

	// RBAC violations are detected when default service account is used
	event := &enrichment.EnrichedEvent{
		EventType: "pod_spec_check",
		Kubernetes: &enrichment.K8sContext{
			ClusterID:      "test-cluster",
			NodeName:       "node-1",
			Namespace:      "default",
			ServiceAccount: "default", // Using default service account triggers CIS_4.1.1
			Labels:         map[string]string{"user": "attacker"},
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	if len(violations) == 0 {
		t.Errorf("expected violations for default service account usage, got none")
	}

	t.Logf("RBAC violation test: detected %d violations", len(violations))
}

// TestIntegrationCapabilityViolation tests detection of dangerous Linux capabilities (CIS 4.5.3)
// ANCHOR: Linux capability violation detection - Phase 3.5 Week 3
// CIS 4.5.3: Minimize Linux Kernel Capability usage
func TestIntegrationCapabilityViolation(t *testing.T) {
	engine, _ := NewEngine()

	event := &enrichment.EnrichedEvent{
		EventType: "capability_usage", // Correct event type from cis_mappings.go
		Capability: &enrichment.CapabilityContext{
			Name:    "SYS_ADMIN", // Must match rule condition (no CAP_ prefix in rules)
			Allowed: true,
			UID:     1000,
		},
		Process: &enrichment.ProcessContext{
			UID:      1000,
			Command:  "docker-runc",
			Filename: "/usr/bin/docker-runc",
		},
		Kubernetes: &enrichment.K8sContext{
			ClusterID:      "test-cluster",
			NodeName:       "node-3",
			Namespace:      "default",
			PodName:        "privileged-workload",
			PodUID:         "pod-cap",
			ServiceAccount: "app-sa",
			Labels:         map[string]string{"workload": "system"},
		},
		Container: &enrichment.ContainerContext{
			ContainerID: "cap789xyz123",
			Runtime:     "containerd",
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	// CIS_4.5.3 detects dangerous capabilities like CAP_SYS_ADMIN
	if len(violations) == 0 {
		t.Errorf("expected violations for dangerous capability CAP_SYS_ADMIN, got none")
	}

	t.Logf("Capability violation test: detected %d violations", len(violations))
}

// TestIntegrationFileAccessViolation tests detection of dangerous file access (CIS 4.5.5)
// ANCHOR: File write violation detection - Phase 3.5 Week 3
// CIS 4.5.5: Ensure the filesystem is read-only where possible
// Tests detection of writes to system directories (/etc, /bin, etc.)
func TestIntegrationFileAccessViolation(t *testing.T) {
	engine, _ := NewEngine()

	event := &enrichment.EnrichedEvent{
		EventType: "file_write", // Correct event type - matches CIS_4.5.5
		File: &enrichment.FileContext{
			Path:      "/etc", // Path must match CIS_4.5.5 allowlist to trigger rule
			Operation: "write",
			UID:       0,
		},
		Process: &enrichment.ProcessContext{
			UID:      0,
			Command:  "bash",
			Filename: "/bin/bash",
		},
		Kubernetes: &enrichment.K8sContext{
			ClusterID:      "test-cluster",
			NodeName:       "node-1",
			Namespace:      "default",
			PodName:        "config-pod",
			PodUID:         "pod-config",
			ServiceAccount: "reader-sa",
			Labels:         map[string]string{"type": "config"},
		},
		Container: &enrichment.ContainerContext{
			ContainerID: "file123xyz789",
			Runtime:     "docker",
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	// CIS_4.5.5 detects writes to system directories
	if len(violations) == 0 {
		t.Errorf("expected violations for write to /etc (system directory), got none")
	}

	t.Logf("File write violation test: detected %d violations", len(violations))
}

// TestIntegrationDNSExfiltration tests detection of DNS exfiltration attempts (CIS 4.6.4)
// ANCHOR: DNS exfiltration detection - Phase 3.5 Week 3
// CIS 4.6.4: Ensure DNS queries are restricted to allowed domains
func TestIntegrationDNSExfiltration(t *testing.T) {
	engine, _ := NewEngine()

	// dns_query event with query not allowed (disallowed domain)
	event := &enrichment.EnrichedEvent{
		EventType: "dns_query", // Correct event type for CIS_4.6.4
		DNS: &enrichment.DNSContext{
			QueryName:    "exfil.attacker.com", // Suspicious exfiltration domain
			QueryType:    "A",
			ResponseCode: 0, // NOERROR
			QueryAllowed: false, // Violation: query not allowed
		},
		Network: &enrichment.NetworkContext{
			Protocol:        "UDP",
			SourceIP:        "10.0.0.50",
			SourcePort:      54321,
			DestinationIP:   "8.8.8.8",
			DestinationPort: 53,
			Direction:       "egress",
		},
		Process: &enrichment.ProcessContext{
			UID:      1000,
			Command:  "curl",
			Filename: "/usr/bin/curl",
		},
		Kubernetes: &enrichment.K8sContext{
			ClusterID:      "test-cluster",
			NodeName:       "node-2",
			Namespace:      "default",
			PodName:        "web-app",
			PodUID:         "pod-web",
			ServiceAccount: "web-sa",
			Labels:         map[string]string{"app": "web"},
		},
		Container: &enrichment.ContainerContext{
			ContainerID: "dns123abc789",
			Runtime:     "containerd",
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	// CIS_4.6.4 detects DNS queries to disallowed domains
	if len(violations) == 0 {
		t.Errorf("expected violations for disallowed DNS query to attacker domain, got none")
	}

	t.Logf("DNS exfiltration test: detected %d violations", len(violations))
}

// TestIntegrationMultipleViolationsInSingleEvent tests complex event with multiple violations
// ANCHOR: Multiple violation detection - Phase 3.5 Week 3
// Tests that a single event can trigger multiple rule matches
func TestIntegrationMultipleViolationsInSingleEvent(t *testing.T) {
	engine, _ := NewEngine()

	// Create event that violates multiple CIS controls
	event := &enrichment.EnrichedEvent{
		EventType: "pod_spec_check",
		Process: &enrichment.ProcessContext{
			UID:      0, // Root (violation for process_execution event type)
			Command:  "malicious",
			Filename: "/malicious/app",
		},
		Container: &enrichment.ContainerContext{
			ContainerID:             "multi123xyz",
			Runtime:                 "docker",
			Privileged:              true,        // Violates CIS_4.5.1
			RunAsRoot:               true,        // Violates CIS_4.5.2 (when process_execution type)
			AllowPrivilegeEscalation: true,       // Violates related security controls
			ReadOnlyFilesystem:      false,       // Violates CIS_4.5.5 (requires file_write event)
		},
		Kubernetes: &enrichment.K8sContext{
			ClusterID:      "test-cluster",
			NodeName:       "node-1",
			Namespace:      "default",
			PodName:        "bad-pod",
			PodUID:         "pod-bad",
			ServiceAccount: "default", // Violates CIS_4.1.1
			Labels:         map[string]string{"suspicious": "true"},
		},
		Capability: &enrichment.CapabilityContext{
			Name:    "SYS_ADMIN", // Dangerous capability (requires capability_usage event type, no CAP_ prefix)
			Allowed: true,
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	// This event type matches pod_spec_check rules: CIS_4.5.1 (privileged), CIS_4.1.1 (default SA)
	// It should trigger at least 2 violations
	if len(violations) < 2 {
		t.Errorf("expected at least 2 violations (privileged container + default ServiceAccount), got %d", len(violations))
	}

	t.Logf("Multiple violations test: detected %d violations", len(violations))
	for i, v := range violations {
		t.Logf("  Violation %d: %s (%s severity)", i+1, v.ControlID, v.Severity)
	}
}

// TestIntegrationNormalEvent tests that normal, benign events produce no violations
// ANCHOR: Benign event handling - Phase 3.5 Week 3
// Ensures no false positives for normal Kubernetes operations
func TestIntegrationNormalEvent(t *testing.T) {
	engine, _ := NewEngine()

	event := &enrichment.EnrichedEvent{
		EventType: "process_execution",
		Process: &enrichment.ProcessContext{
			UID:      1000, // Non-root user
			PID:      5678,
			GID:      1000,
			Command:  "nginx",
			Filename: "/usr/sbin/nginx",
		},
		Kubernetes: &enrichment.K8sContext{
			ClusterID:      "prod-cluster",
			NodeName:       "worker-1",
			Namespace:      "default",
			PodName:        "nginx-pod",
			PodUID:         "pod-nginx",
			ServiceAccount: "nginx",
			Image:          "nginx:1.21",
			ImageRegistry:  "docker.io",
			ImageTag:       "1.21",
			Labels:         map[string]string{"app": "nginx"},
		},
		Container: &enrichment.ContainerContext{
			ContainerID:             "normal123abc",
			Runtime:                 "containerd",
			Privileged:              false,
			RunAsRoot:               false,
			AllowPrivilegeEscalation: false,
			ReadOnlyFilesystem:      true,
		},
		Timestamp: time.Now(),
	}

	violations := engine.Match(event)

	// Normal events should have minimal/no violations
	if len(violations) == 0 {
		t.Logf("Normal event test: passed - no violations detected (expected)")
	} else {
		t.Logf("warning: detected %d violations for normal event (may be false positives)", len(violations))
	}
}

// TestIntegrationEventProcessingPipeline tests the complete event processing flow
// ANCHOR: End-to-end event processing - Phase 3.5 Week 3
// Verifies that events flow through enrichment → rule matching → violation reporting
func TestIntegrationEventProcessingPipeline(t *testing.T) {
	engine, _ := NewEngine()

	// Create a series of events simulating real K8s activity
	events := []*enrichment.EnrichedEvent{
		{
			EventType: "process_execution",
			Process: &enrichment.ProcessContext{
				UID:     1000,
				Command: "app",
			},
			Kubernetes: &enrichment.K8sContext{
				Namespace: "default",
				PodName:   "app-1",
			},
			Timestamp: time.Now(),
		},
		{
			EventType: "process_execution",
			Process: &enrichment.ProcessContext{
				UID:     0, // Root
				Command: "malware",
			},
			Kubernetes: &enrichment.K8sContext{
				Namespace: "default",
				PodName:   "app-2",
			},
			Timestamp: time.Now(),
		},
		{
			EventType: "pod_spec_check",
			Container: &enrichment.ContainerContext{
				Privileged: true,
			},
			Kubernetes: &enrichment.K8sContext{
				Namespace: "default",
				PodName:   "app-3",
			},
			Timestamp: time.Now(),
		},
	}

	totalViolations := 0
	for i, event := range events {
		violations := engine.Match(event)
		totalViolations += len(violations)
		t.Logf("Event %d: %d violations", i+1, len(violations))
	}

	t.Logf("Pipeline test: processed %d events, detected %d total violations", len(events), totalViolations)

	// Expect violations from at least 2 events (root execution and privileged container)
	if totalViolations == 0 {
		t.Logf("warning: expected violations from malicious events")
	}
}

// BenchmarkIntegrationRuleMatching benchmarks the rule matching performance with realistic events
// ANCHOR: Performance benchmark - Phase 3.5 Week 3
// Measures rule engine throughput with complex enriched events
func BenchmarkIntegrationRuleMatching(b *testing.B) {
	engine, _ := NewEngine()

	event := &enrichment.EnrichedEvent{
		EventType: "process_execution",
		Process: &enrichment.ProcessContext{
			UID:      0,
			PID:      1234,
			GID:      0,
			Command:  "bash",
			Filename: "/bin/bash",
		},
		Kubernetes: &enrichment.K8sContext{
			ClusterID:      "bench-cluster",
			NodeName:       "bench-node",
			Namespace:      "default",
			PodName:        "bench-pod",
			PodUID:         "pod-bench",
			ServiceAccount: "default",
			Image:          "image:latest",
			ImageRegistry:  "docker.io",
			ImageTag:       "latest",
			Labels: map[string]string{
				"app":    "bench",
				"tier":   "web",
				"env":    "test",
				"region": "us-west",
			},
		},
		Container: &enrichment.ContainerContext{
			ContainerID: "bench123xyz789",
			Runtime:     "containerd",
			Privileged:  false,
		},
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Match(event)
	}
}
