package kubernetes

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPermissionLevelFromCount(t *testing.T) {
	tests := []struct {
		name  string
		count int
		want  int
	}{
		{name: "restricted", count: 0, want: 0},
		{name: "standard lower", count: 1, want: 1},
		{name: "standard upper", count: 10, want: 1},
		{name: "elevated lower", count: 11, want: 2},
		{name: "elevated upper", count: 100, want: 2},
		{name: "admin", count: 101, want: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := permissionLevelFromCount(tt.count); got != tt.want {
				t.Fatalf("permissionLevelFromCount(%d)=%d want=%d", tt.count, got, tt.want)
			}
		})
	}
}

func TestCountPolicyRulePermissions(t *testing.T) {
	t.Run("counts distinct verbs", func(t *testing.T) {
		rule := rbacv1.PolicyRule{
			Verbs: []string{"get", "list", "watch", "list"},
		}
		if got := countPolicyRulePermissions(rule); got != 3 {
			t.Fatalf("distinct verb count mismatch: got=%d want=3", got)
		}
	})

	t.Run("wildcard verbs are weighted", func(t *testing.T) {
		rule := rbacv1.PolicyRule{
			Verbs: []string{"*"},
		}
		if got := countPolicyRulePermissions(rule); got != wildcardVerbWeight {
			t.Fatalf("wildcard count mismatch: got=%d want=%d", got, wildcardVerbWeight)
		}
	})
}

func TestRBACSubjectMatchesServiceAccount(t *testing.T) {
	if !rbacSubjectMatchesServiceAccount(rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      "sa-a",
		Namespace: "ns-a",
	}, "ns-a", "sa-a") {
		t.Fatalf("expected exact namespace match")
	}

	if !rbacSubjectMatchesServiceAccount(rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      "sa-a",
		Namespace: "",
	}, "ns-a", "sa-a") {
		t.Fatalf("expected empty namespace subject to match")
	}

	if rbacSubjectMatchesServiceAccount(rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      "sa-a",
		Namespace: "other-ns",
	}, "ns-a", "sa-a") {
		t.Fatalf("expected mismatched namespace not to match")
	}
}

func TestHasAPIGroup(t *testing.T) {
	groups := &metav1.APIGroupList{
		Groups: []metav1.APIGroup{
			{Name: "apps"},
			{Name: "rbac.authorization.k8s.io"},
		},
	}
	if !hasAPIGroup(groups, "rbac.authorization.k8s.io") {
		t.Fatalf("expected RBAC API group to be present")
	}
	if hasAPIGroup(groups, "networking.k8s.io") {
		t.Fatalf("did not expect networking group to be present")
	}
}

func TestMaxPermissionCount(t *testing.T) {
	permissions := map[string]int{
		"Role/read-only":         3,
		"ClusterRole/admin-like": 120,
		"Role/view":              7,
	}
	if got := maxPermissionCount(permissions); got != 120 {
		t.Fatalf("expected max permissions 120, got %d", got)
	}

	if got := maxPermissionCount(map[string]int{}); got != 0 {
		t.Fatalf("expected max permissions 0 for empty map, got %d", got)
	}
}
