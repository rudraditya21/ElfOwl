// ANCHOR: Compliance watcher tests - Coverage: pod_spec_check and network_policy_check - Mar 22, 2026
// Validates compliance event construction for K8s API-driven signals.

package agent

import (
	"context"
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
	tokenTTL := int64(1800)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "default",
			UID:       types.UID("pod-uid"),
			Labels:    map[string]string{"app": "web"},
			Annotations: map[string]string{
				"image-scan-status":     "scanned",
				"image-signed":          "true",
				"audit-logging-enabled": "true",
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "sa-1",
			HostNetwork:        true,
			ImagePullSecrets: []corev1.LocalObjectReference{
				{Name: "registry-credentials"},
			},
			SecurityContext: &corev1.PodSecurityContext{
				Sysctls: []corev1.Sysctl{
					{Name: "kernel.dmesg_restrict", Value: "1"},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host-vol",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{Path: "/data"},
					},
				},
				{
					Name: "scratch-vol",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "token-vol",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
										ExpirationSeconds: &tokenTTL,
									},
								},
							},
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:            "c1",
					Image:           "docker.io/library/nginx:1.2",
					ImagePullPolicy: corev1.PullAlways,
					VolumeMounts: []corev1.VolumeMount{
						{Name: "host-vol", MountPath: "/data"},
					},
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
					VolumeMounts: []corev1.VolumeMount{
						{Name: "scratch-vol", MountPath: "/tmp"},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "c1", ContainerID: "containerd://runtime-c1"},
				{Name: "c2", ContainerID: "containerd://runtime-c2"},
			},
		},
	}

	events := agent.buildPodSpecEvents(context.Background(), pod)
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
	if c1.Container.StorageRequest != "1Gi" {
		t.Errorf("expected storage request 1Gi, got %q", c1.Container.StorageRequest)
	}
	if c1.Container.ImageScanStatus != "scanned" {
		t.Errorf("expected image scan status scanned, got %q", c1.Container.ImageScanStatus)
	}
	if !c1.Container.ImageSigned {
		t.Errorf("expected image signed true")
	}
	if !c1.Container.ImageRegistryAuth {
		t.Errorf("expected image registry auth true")
	}
	if c1.Container.VolumeType != "hostPath" {
		t.Errorf("expected volume type hostPath, got %q", c1.Container.VolumeType)
	}
	if c1.Container.Runtime != "containerd" {
		t.Errorf("expected runtime containerd, got %q", c1.Container.Runtime)
	}
	if c1.Container.IsolationLevel != 2 {
		t.Errorf("expected isolation level 2, got %d", c1.Container.IsolationLevel)
	}
	if !c1.Container.KernelHardening {
		t.Errorf("expected kernel hardening true")
	}
	if !c1.Kubernetes.AuditLoggingEnabled {
		t.Errorf("expected audit logging enabled true")
	}
	if c1.Kubernetes.ServiceAccountTokenAge != tokenTTL {
		t.Errorf("expected token age fallback %d, got %d", tokenTTL, c1.Kubernetes.ServiceAccountTokenAge)
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
	if c2.Container.ImageScanStatus != "scanned" {
		t.Errorf("expected image scan status scanned, got %q", c2.Container.ImageScanStatus)
	}
	if !c2.Container.ImageSigned {
		t.Errorf("expected image signed true")
	}
	if !c2.Container.ImageRegistryAuth {
		t.Errorf("expected image registry auth true")
	}
	if c2.Container.VolumeType != "emptyDir" {
		t.Errorf("expected volume type emptyDir, got %q", c2.Container.VolumeType)
	}
	if c2.Container.Runtime != "containerd" {
		t.Errorf("expected runtime containerd, got %q", c2.Container.Runtime)
	}
	if c2.Container.IsolationLevel != 0 {
		t.Errorf("expected isolation level 0, got %d", c2.Container.IsolationLevel)
	}
	if c2.Kubernetes.ServiceAccountTokenAge != tokenTTL {
		t.Errorf("expected token age fallback %d, got %d", tokenTTL, c2.Kubernetes.ServiceAccountTokenAge)
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
