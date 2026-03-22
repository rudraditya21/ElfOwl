// ANCHOR: Compliance watcher tests - Coverage: pod_spec_check and network_policy_check - Mar 22, 2026
// Validates compliance event construction for K8s API-driven signals.

package agent

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ANCHOR: Multi-container pod_spec_check events - Test: per-container compliance - Mar 22, 2026
func TestBuildPodSpecEventsMultiContainer(t *testing.T) {
	agent := &Agent{
		Config: &Config{
			Agent: AgentConfig{
				ClusterID: "cluster-1",
				NodeName:  "node-1",
			},
		},
	}

	priv := true
	allowEsc := false
	readOnly := true

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "default",
			UID:       types.UID("pod-uid"),
			Labels:    map[string]string{"app": "web"},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "sa-1",
			HostNetwork:        true,
			Containers: []corev1.Container{
				{
					Name:            "c1",
					Image:           "docker.io/library/nginx:1.2",
					ImagePullPolicy: corev1.PullAlways,
					SecurityContext: &corev1.SecurityContext{
						Privileged:               &priv,
						AllowPrivilegeEscalation: &allowEsc,
						ReadOnlyRootFilesystem:   &readOnly,
						RunAsNonRoot:             boolPtr(true),
					},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("128Mi"),
							corev1.ResourceCPU:    resource.MustParse("500m"),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceMemory:           resource.MustParse("64Mi"),
							corev1.ResourceCPU:              resource.MustParse("250m"),
							corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
						},
					},
				},
				{
					Name:  "c2",
					Image: "ghcr.io/example/app:2.0",
				},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	events := agent.buildPodSpecEvents(pod)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	byName := map[string]*enrichment.EnrichedEvent{}
	for _, event := range events {
		byName[event.Container.ContainerName] = event
	}

	c1 := byName["c1"]
	if c1 == nil {
		t.Fatalf("missing event for container c1")
	}
	if c1.Kubernetes.ImageRegistry != "docker.io" {
		t.Errorf("expected docker.io registry, got %q", c1.Kubernetes.ImageRegistry)
	}
	if c1.Kubernetes.ImageTag != "1.2" {
		t.Errorf("expected image tag 1.2, got %q", c1.Kubernetes.ImageTag)
	}
	if !c1.Container.Privileged {
		t.Errorf("expected privileged true")
	}
	if c1.Container.AllowPrivilegeEscalation {
		t.Errorf("expected allow_privilege_escalation false")
	}
	if !c1.Container.ReadOnlyFilesystem {
		t.Errorf("expected read_only_filesystem true")
	}
	if c1.Container.MemoryLimit != "128Mi" {
		t.Errorf("expected memory limit 128Mi, got %q", c1.Container.MemoryLimit)
	}
	if c1.Container.CPULimit != "500m" {
		t.Errorf("expected cpu limit 500m, got %q", c1.Container.CPULimit)
	}

	c2 := byName["c2"]
	if c2 == nil {
		t.Fatalf("missing event for container c2")
	}
	if c2.Kubernetes.ImageRegistry != "ghcr.io" {
		t.Errorf("expected ghcr.io registry, got %q", c2.Kubernetes.ImageRegistry)
	}
	if c2.Kubernetes.ImageTag != "2.0" {
		t.Errorf("expected image tag 2.0, got %q", c2.Kubernetes.ImageTag)
	}
}

// ANCHOR: network_policy_check event builder - Test: default deny flag propagation - Mar 22, 2026
func TestBuildNetworkPolicyEvent(t *testing.T) {
	agent := &Agent{
		Config: &Config{
			Agent: AgentConfig{
				ClusterID: "cluster-1",
				NodeName:  "node-1",
			},
		},
	}

	netpol := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "np-1",
			Namespace: "default",
		},
	}

	event := agent.buildNetworkPolicyEvent(netpol, true)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.EventType != "network_policy_check" {
		t.Errorf("expected event type network_policy_check, got %q", event.EventType)
	}
	if event.Kubernetes == nil || event.Kubernetes.Namespace != "default" {
		t.Errorf("expected namespace default, got %+v", event.Kubernetes)
	}
	if !event.Kubernetes.HasDefaultDenyNetworkPolicy {
		t.Errorf("expected default deny policy flag true")
	}
}

// ANCHOR: Pod phase filter - Test: running-only compliance events - Mar 22, 2026
func TestShouldProcessPod(t *testing.T) {
	runningPod := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	pendingPod := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending}}

	if !shouldProcessPod(runningPod) {
		t.Error("expected running pod to be processed")
	}
	if shouldProcessPod(pendingPod) {
		t.Error("expected pending pod to be skipped")
	}
	if shouldProcessPod(nil) {
		t.Error("expected nil pod to be skipped")
	}
}

// ANCHOR: Test helper for bool pointers - Utility: reduce inline literals - Mar 22, 2026
func boolPtr(value bool) *bool {
	return &value
}
