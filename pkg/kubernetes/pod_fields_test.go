package kubernetes

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestContainerRuntimeFromPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"container-runtime.web": "cri-o",
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "web", ContainerID: "containerd://abc"},
			},
		},
	}

	if got := ContainerRuntimeFromPod(pod, "web"); got != "cri-o" {
		t.Fatalf("expected runtime override cri-o, got %q", got)
	}

	delete(pod.Annotations, "container-runtime.web")
	if got := ContainerRuntimeFromPod(pod, "web"); got != "containerd" {
		t.Fatalf("expected runtime containerd, got %q", got)
	}
}

func TestIsolationLevelForContainer(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{},
		},
	}

	runAsNonRoot := true
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := true
	privileged := false
	container := corev1.Container{
		Name: "web",
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             &runAsNonRoot,
			AllowPrivilegeEscalation: &allowPrivilegeEscalation,
			ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
			Privileged:               &privileged,
		},
	}

	level := IsolationLevelForContainer(pod, container)
	if level < 2 {
		t.Fatalf("expected isolation level >=2, got %d", level)
	}
}

func TestAuditLoggingEnabledFromPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"audit-logging-enabled": "true",
			},
		},
	}
	enabled, ok := AuditLoggingEnabledFromPod(pod)
	if !ok || !enabled {
		t.Fatalf("expected audit logging override true, got enabled=%v ok=%v", enabled, ok)
	}
}

func TestServiceAccountTokenTTLFromPod(t *testing.T) {
	ttl := int64(1800)
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "token-vol",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
										ExpirationSeconds: &ttl,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if got := ServiceAccountTokenTTLFromPod(pod); got != ttl {
		t.Fatalf("expected token ttl %d, got %d", ttl, got)
	}
}
