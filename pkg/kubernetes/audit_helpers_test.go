package kubernetes

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsAPIServerPod(t *testing.T) {
	if !isAPIServerPod(corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-node1"}}) {
		t.Fatalf("expected kube-apiserver name match")
	}
	if !isAPIServerPod(corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"component": "kube-apiserver"}}}) {
		t.Fatalf("expected kube-apiserver component label match")
	}
	if isAPIServerPod(corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "coredns"}}) {
		t.Fatalf("did not expect non-apiserver pod to match")
	}
}

func TestHasAuditFlags(t *testing.T) {
	if !hasAuditFlags([]string{"kube-apiserver", "--audit-log-path=/var/log/audit.log"}, nil) {
		t.Fatalf("expected audit flag match in command")
	}
	if !hasAuditFlags(nil, []string{"--audit-policy-file=/etc/kubernetes/audit.yaml"}) {
		t.Fatalf("expected audit flag match in args")
	}
	if hasAuditFlags([]string{"kube-apiserver"}, []string{"--secure-port=6443"}) {
		t.Fatalf("did not expect non-audit flags to match")
	}
}
