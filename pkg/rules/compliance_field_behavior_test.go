package rules

import (
	"testing"
	"time"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

func TestCIS491ContainerRuntimeBehavior(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	base := &enrichment.EnrichedEvent{
		EventType: "pod_spec_check",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID:                    "c-1",
			NodeName:                     "n-1",
			Namespace:                    "default",
			PodName:                      "p-1",
			PodUID:                       "uid-1",
			ServiceAccount:               "sa-1",
			AutomountServiceAccountToken: false,
			RBACPolicyDefined:            true,
			RolePermissionCount:          1,
			ServiceAccountPermissions:    1,
			AuditLoggingEnabled:          true,
		},
		Container: &enrichment.ContainerContext{
			ContainerName: "app",
			Runtime:       "containerd",
		},
	}

	violations := engine.Match(base)
	if hasControl(violations, "CIS_4.9.1") {
		t.Fatalf("did not expect CIS_4.9.1 when runtime is containerd")
	}

	base.Container.Runtime = "docker"
	violations = engine.Match(base)
	if !hasControl(violations, "CIS_4.9.1") {
		t.Fatalf("expected CIS_4.9.1 when runtime is docker")
	}

	base.Container.Runtime = "unknown"
	violations = engine.Match(base)
	if !hasControl(violations, "CIS_4.9.1") {
		t.Fatalf("expected CIS_4.9.1 when runtime is unknown")
	}
}

func TestCIS431RegistryAllowlistBehavior(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	base := &enrichment.EnrichedEvent{
		EventType: "pod_spec_check",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID:     "c-1",
			NodeName:      "n-1",
			Namespace:     "default",
			PodName:       "p-1",
			PodUID:        "uid-1",
			ImageRegistry: "ghcr.io",
		},
		Container: &enrichment.ContainerContext{
			ContainerName: "app",
			Runtime:       "containerd",
		},
	}

	violations := engine.Match(base)
	if hasControl(violations, "CIS_4.3.1") {
		t.Fatalf("did not expect CIS_4.3.1 for approved registry ghcr.io")
	}

	base.Kubernetes.ImageRegistry = "unknown.registry.internal"
	violations = engine.Match(base)
	if !hasControl(violations, "CIS_4.3.1") {
		t.Fatalf("expected CIS_4.3.1 for non-approved registry")
	}
}

func TestNoDuplicateSeccompViolationsPerProcessEvent(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	event := &enrichment.EnrichedEvent{
		EventType: "process_execution",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID: "c-1",
			NodeName:  "n-1",
			Namespace: "default",
			PodName:   "p-1",
			PodUID:    "uid-1",
		},
		Container: &enrichment.ContainerContext{
			ContainerName:   "app",
			SeccompProfile:  "unconfined",
			ApparmorProfile: "runtime/default",
		},
		Process: &enrichment.ProcessContext{
			PID: 100,
			UID: 1000,
		},
	}

	violations := engine.Match(event)
	if !hasControl(violations, "CIS_4.2.7") {
		t.Fatalf("expected CIS_4.2.7 for process_execution seccomp unconfined")
	}
	if hasControl(violations, "CIS_4.7.1") {
		t.Fatalf("did not expect CIS_4.7.1 on process_execution event")
	}
}

func TestNoDuplicateAppArmorViolationsPerProcessEvent(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	event := &enrichment.EnrichedEvent{
		EventType: "process_execution",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID: "c-1",
			NodeName:  "n-1",
			Namespace: "default",
			PodName:   "p-1",
			PodUID:    "uid-1",
		},
		Container: &enrichment.ContainerContext{
			ContainerName:   "app",
			SeccompProfile:  "runtime/default",
			ApparmorProfile: "unconfined",
		},
		Process: &enrichment.ProcessContext{
			PID: 100,
			UID: 1000,
		},
	}

	violations := engine.Match(event)
	if !hasControl(violations, "CIS_4.2.8") {
		t.Fatalf("expected CIS_4.2.8 for process_execution apparmor unconfined")
	}
	if hasControl(violations, "CIS_4.7.2") {
		t.Fatalf("did not expect CIS_4.7.2 on process_execution event")
	}
}

func TestPodSpecSeccompRuleTargetsMissingProfile(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	event := &enrichment.EnrichedEvent{
		EventType: "pod_spec_check",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID: "c-1",
			NodeName:  "n-1",
			Namespace: "default",
			PodName:   "p-1",
			PodUID:    "uid-1",
		},
		Container: &enrichment.ContainerContext{
			ContainerName:  "app",
			SeccompProfile: "",
		},
	}

	violations := engine.Match(event)
	if !hasControl(violations, "CIS_4.7.1") {
		t.Fatalf("expected CIS_4.7.1 when seccomp profile is missing on pod_spec_check")
	}

	event.Container.SeccompProfile = "unconfined"
	violations = engine.Match(event)
	if hasControl(violations, "CIS_4.7.1") {
		t.Fatalf("did not expect CIS_4.7.1 when seccomp profile is explicitly set")
	}
}

func TestPodSpecAppArmorRuleTargetsMissingProfile(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	event := &enrichment.EnrichedEvent{
		EventType: "pod_spec_check",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID: "c-1",
			NodeName:  "n-1",
			Namespace: "default",
			PodName:   "p-1",
			PodUID:    "uid-1",
		},
		Container: &enrichment.ContainerContext{
			ContainerName:   "app",
			ApparmorProfile: "",
		},
	}

	violations := engine.Match(event)
	if !hasControl(violations, "CIS_4.7.2") {
		t.Fatalf("expected CIS_4.7.2 when apparmor profile is missing on pod_spec_check")
	}

	event.Container.ApparmorProfile = "unconfined"
	violations = engine.Match(event)
	if hasControl(violations, "CIS_4.7.2") {
		t.Fatalf("did not expect CIS_4.7.2 when apparmor profile is explicitly set")
	}
}

func TestCIS492IsolationLevelBehavior(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	event := &enrichment.EnrichedEvent{
		EventType: "process_execution",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID: "c-1",
			NodeName:  "n-1",
			Namespace: "default",
			PodName:   "p-1",
			PodUID:    "uid-1",
		},
		Container: &enrichment.ContainerContext{
			ContainerName:  "app",
			IsolationLevel: 1,
			SeccompProfile: "RuntimeDefault",
		},
		Process: &enrichment.ProcessContext{
			PID: 100,
			UID: 1000,
		},
	}

	violations := engine.Match(event)
	if hasControl(violations, "CIS_4.9.2") {
		t.Fatalf("did not expect CIS_4.9.2 when isolation level is 1")
	}

	event.Container.IsolationLevel = 0
	violations = engine.Match(event)
	if !hasControl(violations, "CIS_4.9.2") {
		t.Fatalf("expected CIS_4.9.2 when isolation level is 0")
	}
}

func TestCIS551AuditLoggingBehavior(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	event := &enrichment.EnrichedEvent{
		EventType: "pod_spec_check",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID:                    "c-1",
			NodeName:                     "n-1",
			Namespace:                    "default",
			PodName:                      "p-1",
			PodUID:                       "uid-1",
			ServiceAccount:               "sa-1",
			AutomountServiceAccountToken: false,
			RBACPolicyDefined:            true,
			RolePermissionCount:          1,
			ServiceAccountPermissions:    1,
			AuditLoggingEnabled:          false,
		},
		Container: &enrichment.ContainerContext{
			ContainerName: "app",
			Runtime:       "docker",
		},
	}

	violations := engine.Match(event)
	if !hasControl(violations, "CIS_5.5.1") {
		t.Fatalf("expected CIS_5.5.1 when audit logging is disabled")
	}

	event.Kubernetes.AuditLoggingEnabled = true
	violations = engine.Match(event)
	if hasControl(violations, "CIS_5.5.1") {
		t.Fatalf("did not expect CIS_5.5.1 when audit logging is enabled")
	}
}

func hasControl(violations []*Violation, controlID string) bool {
	for _, v := range violations {
		if v != nil && v.ControlID == controlID {
			return true
		}
	}
	return false
}
