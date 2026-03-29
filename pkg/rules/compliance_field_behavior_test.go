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
	if !hasControl(violations, "CIS_4.9.1") {
		t.Fatalf("expected CIS_4.9.1 when runtime is containerd")
	}

	base.Container.Runtime = "docker"
	violations = engine.Match(base)
	if hasControl(violations, "CIS_4.9.1") {
		t.Fatalf("did not expect CIS_4.9.1 when runtime is docker")
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
	if !hasControl(violations, "CIS_4.9.2") {
		t.Fatalf("expected CIS_4.9.2 when isolation level is 1")
	}

	event.Container.IsolationLevel = 2
	violations = engine.Match(event)
	if hasControl(violations, "CIS_4.9.2") {
		t.Fatalf("did not expect CIS_4.9.2 when isolation level is 2")
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
