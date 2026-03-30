package kubernetes

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestFormatAndParseNamespacedPodContainerMapping(t *testing.T) {
	t.Run("with container", func(t *testing.T) {
		mapping := formatNamespacedPodContainerMapping("default", "pod-a", "sidecar")
		ns, pod, container, ok := parseNamespacedPodContainerMapping(mapping)
		if !ok {
			t.Fatalf("expected mapping to parse")
		}
		if ns != "default" || pod != "pod-a" || container != "sidecar" {
			t.Fatalf("unexpected parsed values: ns=%q pod=%q container=%q", ns, pod, container)
		}
	})

	t.Run("without container", func(t *testing.T) {
		mapping := formatNamespacedPodContainerMapping("default", "pod-a", "")
		ns, pod, container, ok := parseNamespacedPodContainerMapping(mapping)
		if !ok {
			t.Fatalf("expected mapping to parse")
		}
		if ns != "default" || pod != "pod-a" || container != "" {
			t.Fatalf("unexpected parsed values: ns=%q pod=%q container=%q", ns, pod, container)
		}
	})

	t.Run("invalid mapping", func(t *testing.T) {
		if _, _, _, ok := parseNamespacedPodContainerMapping("bad-format"); ok {
			t.Fatalf("expected invalid mapping to fail parse")
		}
	})
}

func TestFindContainerNameForIDAcrossAllStatusKinds(t *testing.T) {
	client := &Client{}
	pod := corev1.Pod{}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:        "app",
		ContainerID: "containerd://abc-main",
	}}
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name:        "init-setup",
		ContainerID: "containerd://abc-init",
	}}
	pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{
		Name:        "debugger",
		ContainerID: "containerd://abc-ephemeral",
	}}

	if got, ok := findContainerNameForID(client, pod, "abc-main"); !ok || got != "app" {
		t.Fatalf("expected app container match, got %q ok=%v", got, ok)
	}
	if got, ok := findContainerNameForID(client, pod, "abc-init"); !ok || got != "init-setup" {
		t.Fatalf("expected init container match, got %q ok=%v", got, ok)
	}
	if got, ok := findContainerNameForID(client, pod, "abc-ephemeral"); !ok || got != "debugger" {
		t.Fatalf("expected ephemeral container match, got %q ok=%v", got, ok)
	}
}
