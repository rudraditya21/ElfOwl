package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsAuditLoggingEnabledUnknownFailsClosed(t *testing.T) {
	c := &Client{
		listKubeSystemPods: func(ctx context.Context) (*corev1.PodList, error) {
			return nil, errors.New("pods unavailable")
		},
	}

	if c.IsAuditLoggingEnabled(context.Background()) {
		t.Fatalf("expected false when audit status is unknown on first check")
	}
}

func TestIsAuditLoggingEnabledUsesMemoOnUnknown(t *testing.T) {
	c := &Client{
		listKubeSystemPods: func(ctx context.Context) (*corev1.PodList, error) {
			return nil, errors.New("pods unavailable")
		},
		auditMemo: auditLoggingMemo{
			enabled:   true,
			checked:   true,
			checkedAt: time.Now().Add(-auditLoggingCacheTTL - time.Second),
		},
	}

	if !c.IsAuditLoggingEnabled(context.Background()) {
		t.Fatalf("expected memoized true on unknown detection after prior check")
	}
}

func TestIsAuditLoggingEnabledDetectsEnabled(t *testing.T) {
	c := &Client{
		listKubeSystemPods: func(ctx context.Context) (*corev1.PodList, error) {
			return &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-node-1"},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Command: []string{"kube-apiserver", "--audit-log-path=/var/log/kubernetes/audit.log"},
								},
							},
						},
					},
				},
			}, nil
		},
	}

	if !c.IsAuditLoggingEnabled(context.Background()) {
		t.Fatalf("expected true when audit flags are present")
	}
}

func TestIsAuditLoggingEnabledHiddenControlPlaneFailsClosed(t *testing.T) {
	c := &Client{
		listKubeSystemPods: func(ctx context.Context) (*corev1.PodList, error) {
			return &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "coredns-abc"},
					},
				},
			}, nil
		},
	}

	if c.IsAuditLoggingEnabled(context.Background()) {
		t.Fatalf("expected false when kube-apiserver pods are not visible")
	}
}
