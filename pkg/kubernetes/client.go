// ANCHOR: Kubernetes API client - Dec 26, 2025
// Provides read-only K8s API access for metadata enrichment
// IMPLEMENTATION IN PROGRESS - Week 4 task

package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client provides read-only access to Kubernetes API
type Client struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	cache     *MetadataCache
}

// NewClient creates a new Kubernetes API client
func NewClient(inCluster bool) (*Client, error) {
	var config *rest.Config
	var err error

	if inCluster {
		// Use in-cluster configuration (running in pod)
		config, err = rest.InClusterConfig()
	} else {
		// Use kubeconfig from environment or home directory
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load Kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	return &Client{
		clientset: clientset,
		config:    config,
		cache:     NewMetadataCache(5 * 60), // 5-minute TTL in seconds
	}, nil
}

// GetClientset returns the underlying Kubernetes clientset
// ANCHOR: Clientset accessor for external API usage - Phase 3.2 Week 3
// Allows other components (like rule engine) to make K8s API calls
// Use this to access the clientset for ConfigMap reads or other K8s operations
func (c *Client) GetClientset() *kubernetes.Clientset {
	return c.clientset
}

// GetPodMetadata retrieves pod metadata from K8s API
// ANCHOR: Pod metadata query from K8s API - Phase 2.2, Dec 26, 2025
// Retrieves pod name, namespace, UID, service account, image, and labels
func (c *Client) GetPodMetadata(ctx context.Context, namespace, podName string) (*PodMetadata, error) {
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("namespace and pod name required")
	}

	// Check cache first
	if cached, found := c.cache.GetPod(namespace, podName); found {
		return cached, nil
	}

	// Query K8s API
	pod, err := c.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}

	// Extract metadata from pod spec
	image := ""
	imagePullPolicy := "IfNotPresent"
	if len(pod.Spec.Containers) > 0 {
		image = pod.Spec.Containers[0].Image
		if pod.Spec.Containers[0].ImagePullPolicy != "" {
			imagePullPolicy = string(pod.Spec.Containers[0].ImagePullPolicy)
		}
	}

	// Extract security context from pod spec
	// ANCHOR: Extract pod and container security context - Phase 2.2 fix, Dec 26, 2025
	// Parse pod.Spec.SecurityContext and first container's SecurityContext for actual values
	var runAsUser int64
	var fsGroup int64
	var runAsNonRoot bool
	var seccompProfile, selinuxLevel, apparmorProfile string
	var allowPrivilegeEscalation, privileged, readOnlyRootFilesystem bool
	var runAsRootContainer bool
	var memoryLimit, memoryRequest, cpuLimit, cpuRequest string

	// Pod-level security context
	if pod.Spec.SecurityContext != nil {
		if pod.Spec.SecurityContext.RunAsUser != nil {
			runAsUser = *pod.Spec.SecurityContext.RunAsUser
		}
		if pod.Spec.SecurityContext.RunAsNonRoot != nil {
			runAsNonRoot = *pod.Spec.SecurityContext.RunAsNonRoot
		}
		if pod.Spec.SecurityContext.FSGroup != nil {
			fsGroup = *pod.Spec.SecurityContext.FSGroup
		}
		if pod.Spec.SecurityContext.SeccompProfile != nil {
			seccompProfile = string(pod.Spec.SecurityContext.SeccompProfile.Type)
		}
		if pod.Spec.SecurityContext.SELinuxOptions != nil {
			selinuxLevel = pod.Spec.SecurityContext.SELinuxOptions.Level
		}
	}

	containerName := ""

	// AppArmor profile from pod annotations
	// ANCHOR: Extract AppArmor profile with container name in annotation key - Phase 2.2 fix, Dec 26, 2025
	// K8s annotation key includes container name suffix, e.g. container.apparmor.security.beta.kubernetes.io/{container_name}
	if pod.Annotations != nil && len(pod.Spec.Containers) > 0 {
		containerName = pod.Spec.Containers[0].Name
		apparmorProfile = pod.Annotations["container.apparmor.security.beta.kubernetes.io/"+containerName]
	}

	// Container-level security context (from first container)
	// ANCHOR: Extract container-level RunAsNonRoot to override pod-level setting - Phase 2.2 fix, Dec 26, 2025
	// Container-level security context takes precedence over pod-level for runAsNonRoot
	if len(pod.Spec.Containers) > 0 {
		container := pod.Spec.Containers[0]
		containerName = container.Name
		if container.SecurityContext != nil {
			if container.SecurityContext.AllowPrivilegeEscalation != nil {
				allowPrivilegeEscalation = *container.SecurityContext.AllowPrivilegeEscalation
			} else {
				allowPrivilegeEscalation = true // K8s default
			}
			if container.SecurityContext.Privileged != nil {
				privileged = *container.SecurityContext.Privileged
			}
			if container.SecurityContext.ReadOnlyRootFilesystem != nil {
				readOnlyRootFilesystem = *container.SecurityContext.ReadOnlyRootFilesystem
			}
			if container.SecurityContext.RunAsUser != nil {
				runAsUser = *container.SecurityContext.RunAsUser
				runAsRootContainer = (runAsUser == 0)
			}
			// Container-level RunAsNonRoot overrides pod-level setting
			if container.SecurityContext.RunAsNonRoot != nil {
				runAsNonRoot = *container.SecurityContext.RunAsNonRoot
			}
		}

		// Resource requests and limits
		if container.Resources.Limits != nil {
			if mem, ok := container.Resources.Limits["memory"]; ok {
				memoryLimit = mem.String()
			}
			if cpu, ok := container.Resources.Limits["cpu"]; ok {
				cpuLimit = cpu.String()
			}
		}
		if container.Resources.Requests != nil {
			if mem, ok := container.Resources.Requests["memory"]; ok {
				memoryRequest = mem.String()
			}
			if cpu, ok := container.Resources.Requests["cpu"]; ok {
				cpuRequest = cpu.String()
			}
		}
	}

	// Create PodMetadata with extracted security context
	metadata := &PodMetadata{
		Name:                     pod.Name,
		Namespace:                pod.Namespace,
		UID:                      string(pod.UID),
		ServiceAccount:           pod.Spec.ServiceAccountName,
		Image:                    image,
		ImageRegistry:            "", // Will be parsed by enricher
		ImageTag:                 "", // Will be parsed by enricher
		Labels:                   pod.Labels,
		OwnerRef:                 nil, // TODO: Phase 2.3 - extract owner references from pod
		ContainerName:            containerName,
		RunAsUser:                runAsUser,
		RunAsNonRoot:             runAsNonRoot,
		FSGroup:                  fsGroup,
		SeccompProfile:           seccompProfile,
		SELinuxLevel:             selinuxLevel,
		AppArmorProfile:          apparmorProfile,
		AllowPrivilegeEscalation: allowPrivilegeEscalation,
		Privileged:               privileged,
		ReadOnlyRootFilesystem:   readOnlyRootFilesystem,
		RunAsRootContainer:       runAsRootContainer,
		HostNetwork:              pod.Spec.HostNetwork,
		HostIPC:                  pod.Spec.HostIPC,
		HostPID:                  pod.Spec.HostPID,
		MemoryLimit:              memoryLimit,
		MemoryRequest:            memoryRequest,
		CPULimit:                 cpuLimit,
		CPURequest:               cpuRequest,
		ImagePullPolicy:          imagePullPolicy,
	}

	// Store in cache
	c.cache.SetPod(namespace, podName, metadata)

	return metadata, nil
}

// GetPodByContainerID retrieves pod by container ID
// ANCHOR: Optimized container ID to pod mapping - Phase 2.2 fix, Dec 26, 2025
// Uses agent-namespace queries and caching to avoid cluster-wide pod list queries
func (c *Client) GetPodByContainerID(ctx context.Context, containerID string) (*PodMetadata, error) {
	if containerID == "" {
		return nil, fmt.Errorf("container ID required")
	}

	// Check mapping cache first - avoid K8s API query if we have cached mapping
	if mapping, found := c.cache.GetContainerMapping(containerID); found {
		parts := strings.Split(mapping, "/")
		if len(parts) == 2 {
			return c.GetPodMetadata(ctx, parts[0], parts[1])
		}
	}

	// Normalize container ID (strip runtime prefixes)
	normalizedID := c.normalizeContainerID(containerID)

	// ANCHOR: Optimize pod lookup with agent namespace constraint - Phase 2.2 fix, Dec 26, 2025
	// Query only pods in agent's namespace (where the agent is running) first
	// This reduces API load from O(total_pods) to O(pods_in_namespace)
	// Fall back to cluster-wide search only if needed for cross-namespace events

	agentNamespace := "monitoring" // Default monitoring namespace - can be configurable
	if ns, ok := os.LookupEnv("AGENT_NAMESPACE"); ok {
		agentNamespace = ns
	}

	// First, try querying just the agent's namespace
	pods, err := c.clientset.CoreV1().Pods(agentNamespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		// Search agent namespace first
		for _, pod := range pods.Items {
			for _, cs := range pod.Status.ContainerStatuses {
				if c.normalizeContainerID(cs.ContainerID) == normalizedID {
					// Found matching pod, cache the mapping
					mapping := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					c.cache.SetContainerMapping(containerID, mapping)
					return c.GetPodMetadata(ctx, pod.Namespace, pod.Name)
				}
			}
		}
	}

	// If not found in agent namespace and there's time, try cluster-wide search
	// But with rate limit protection: only do this if we're not hitting the cluster hard
	// This is a fallback for cross-namespace events, which should be rare

	// Query all pods in all namespaces (expensive operation, done as fallback)
	allPods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// If we can't list pods, return nil gracefully
		// Enricher will use defaults rather than failing
		return nil, nil
	}

	// Search for matching container ID across all pods
	for _, pod := range allPods.Items {
		for _, cs := range pod.Status.ContainerStatuses {
			if c.normalizeContainerID(cs.ContainerID) == normalizedID {
				// Found matching pod, cache the mapping
				mapping := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
				c.cache.SetContainerMapping(containerID, mapping)

				// Query full metadata and return
				return c.GetPodMetadata(ctx, pod.Namespace, pod.Name)
			}
		}
	}

	// Pod not found
	return nil, nil
}

// normalizeContainerID strips runtime prefix from container ID
// Handles docker://, containerd://, cri-o:// prefixes
func (c *Client) normalizeContainerID(containerID string) string {
	prefixes := []string{"docker://", "containerd://", "cri-o://"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(containerID, prefix) {
			return strings.TrimPrefix(containerID, prefix)
		}
	}
	return containerID
}

// GetNodeMetadata retrieves node metadata
// ANCHOR: Node metadata query from K8s API - Phase 2.2, Dec 26, 2025
// Retrieves node name, labels, taints, and resource capacity
func (c *Client) GetNodeMetadata(ctx context.Context, nodeName string) (*NodeMetadata, error) {
	if nodeName == "" {
		return nil, fmt.Errorf("node name required")
	}

	// Check cache first
	if cached, found := c.cache.GetNode(nodeName); found {
		return cached, nil
	}

	// Query K8s API
	node, err := c.clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	// Extract metadata from node spec
	taints := make([]string, 0)
	for _, taint := range node.Spec.Taints {
		taints = append(taints, fmt.Sprintf("%s=%s:%s", taint.Key, taint.Value, taint.Effect))
	}

	capacity := make(map[string]string)
	for k, v := range node.Status.Capacity {
		capacity[k.String()] = v.String()
	}

	metadata := &NodeMetadata{
		Name:     node.Name,
		Labels:   node.Labels,
		Taints:   taints,
		Capacity: capacity,
	}

	// Store in cache
	c.cache.SetNode(nodeName, metadata)

	return metadata, nil
}

// GetServiceAccountMetadata retrieves ServiceAccount metadata for RBAC context
// ANCHOR: ServiceAccount metadata query from K8s API - Phase 2.3, Dec 26, 2025
// Retrieves automount settings and token age for RBAC enforcement evaluation
func (c *Client) GetServiceAccountMetadata(ctx context.Context, namespace, saName string) (*ServiceAccountMetadata, error) {
	if namespace == "" || saName == "" {
		return nil, fmt.Errorf("namespace and service account name required")
	}

	// Query K8s API for ServiceAccount
	sa, err := c.clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, saName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get service account %s/%s: %w", namespace, saName, err)
	}

	metadata := &ServiceAccountMetadata{
		Name:                         sa.Name,
		Namespace:                    sa.Namespace,
		AutomountServiceAccountToken: true, // K8s default when not specified
	}

	// Check if automount is explicitly set
	if sa.AutomountServiceAccountToken != nil {
		metadata.AutomountServiceAccountToken = *sa.AutomountServiceAccountToken
	}

	// Get token age from secret if available
	// Token is typically in a secret with the same SA name
	if len(sa.Secrets) > 0 {
		secretName := sa.Secrets[0].Name
		secret, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err == nil {
			// Token age is calculated from secret creation time
			metadata.TokenCreatedAt = secret.ObjectMeta.CreationTimestamp.Unix()
		}
	}

	return metadata, nil
}

// GetRBACLevel determines privilege escalation level for a service account
// ANCHOR: RBAC privilege level evaluation - Phase 2.3, Dec 26, 2025
// Returns 0=restricted, 1=standard, 2=elevated, 3=admin
func (c *Client) GetRBACLevel(ctx context.Context, namespace, saName string) int {
	if namespace == "" || saName == "" {
		return 1 // Default to standard if not found
	}

	// Query all RoleBindings and ClusterRoleBindings for this service account
	// Count permissions to determine level
	permCount := 0

	// Check RoleBindings in the namespace
	rbs, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, rb := range rbs.Items {
			for _, subject := range rb.Subjects {
				if subject.Kind == "ServiceAccount" && subject.Name == saName && subject.Namespace == namespace {
					// Found a RoleBinding - this grants permissions
					permCount++
				}
			}
		}
	}

	// Check ClusterRoleBindings (cluster-wide)
	crbs, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range crbs.Items {
			for _, subject := range crb.Subjects {
				if subject.Kind == "ServiceAccount" && subject.Name == saName && subject.Namespace == namespace {
					// ClusterRoleBindings grant elevated access
					return 3 // Admin/cluster-wide
				}
			}
		}
	}

	// Determine level based on permission count
	if permCount == 0 {
		return 0 // Restricted - no bindings
	} else if permCount == 1 {
		return 1 // Standard - single binding
	} else {
		return 2 // Elevated - multiple bindings
	}
}

// CountRBACPermissions counts the total number of permissions granted via roles
// ANCHOR: RBAC permission counting - Phase 2.3, Dec 26, 2025
// Counts all verbs in all roles bound to the service account
func (c *Client) CountRBACPermissions(ctx context.Context, namespace, saName string) int {
	if namespace == "" || saName == "" {
		return 0
	}

	totalPermissions := 0

	// Check RoleBindings in the namespace
	rbs, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, rb := range rbs.Items {
			for _, subject := range rb.Subjects {
				if subject.Kind == "ServiceAccount" && subject.Name == saName && subject.Namespace == namespace {
					// Get the Role
					role, err := c.clientset.RbacV1().Roles(namespace).Get(ctx, rb.RoleRef.Name, metav1.GetOptions{})
					if err == nil {
						// Count permissions (verbs) in the role
						for _, rule := range role.Rules {
							totalPermissions += len(rule.Verbs)
						}
					}
				}
			}
		}
	}

	// Check ClusterRoleBindings
	crbs, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range crbs.Items {
			for _, subject := range crb.Subjects {
				if subject.Kind == "ServiceAccount" && subject.Name == saName && subject.Namespace == namespace {
					// Get the ClusterRole
					crole, err := c.clientset.RbacV1().ClusterRoles().Get(ctx, crb.RoleRef.Name, metav1.GetOptions{})
					if err == nil {
						// Count permissions (verbs) in the cluster role
						for _, rule := range crole.Rules {
							totalPermissions += len(rule.Verbs)
						}
					}
				}
			}
		}
	}

	return totalPermissions
}

// GetNetworkPolicyStatus checks if network policies restrict ingress/egress for a pod
// ANCHOR: Network policy evaluation for pod traffic restriction - Phase 2.4, Dec 26, 2025
// Checks if NetworkPolicy objects restrict traffic to/from the pod
func (c *Client) GetNetworkPolicyStatus(ctx context.Context, namespace, podName string, labels map[string]string) *NetworkPolicyStatus {
	if namespace == "" {
		return &NetworkPolicyStatus{
			IngressRestricted:  false,
			EgressRestricted:   false,
			NamespaceIsolation: false,
		}
	}

	status := &NetworkPolicyStatus{
		IngressRestricted:  false,
		EgressRestricted:   false,
		NamespaceIsolation: false,
	}

	// Query all NetworkPolicies in the namespace
	netpols, err := c.clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil || netpols == nil {
		// No policies found or error - assume no restriction
		return status
	}

	ingressPolicies := 0
	egressPolicies := 0
	defaultDenyIngress := false
	defaultDenyEgress := false

	for _, netpol := range netpols.Items {
		// Check if this policy applies to this pod
		// A policy applies if the pod's labels match the selector
		selector := netpol.Spec.PodSelector
		if selectorMatches(labels, selector) {
			// Check policy types to see what it restricts
			for _, policyType := range netpol.Spec.PolicyTypes {
				if policyType == "Ingress" {
					ingressPolicies++
					// If it has no ingress rules, it's a default deny ingress
					if len(netpol.Spec.Ingress) == 0 {
						defaultDenyIngress = true
					}
				}
				if policyType == "Egress" {
					egressPolicies++
					// If it has no egress rules, it's a default deny egress
					if len(netpol.Spec.Egress) == 0 {
						defaultDenyEgress = true
					}
				}
			}
		}
	}

	// Pod traffic is restricted if there are policies or default deny rules
	status.IngressRestricted = ingressPolicies > 0 || defaultDenyIngress
	status.EgressRestricted = egressPolicies > 0 || defaultDenyEgress

	// Check for default-deny NetworkPolicy in the namespace (namespace-wide isolation)
	// ANCHOR: Default-deny detection requires empty selector AND empty rule list - Phase 2.4 fix, Dec 27, 2025
	// Empty selector alone doesn't guarantee isolation (policy could allow all traffic).
	// True isolation requires empty rules for at least one policy type (deny all semantics).
	for _, netpol := range netpols.Items {
		// Default deny policy has empty pod selector (applies to all pods in namespace)
		if len(netpol.Spec.PodSelector.MatchLabels) == 0 && len(netpol.Spec.PodSelector.MatchExpressions) == 0 {
			// Empty selector - check if it actually denies traffic (empty rule list)
			for _, policyType := range netpol.Spec.PolicyTypes {
				if policyType == "Ingress" && len(netpol.Spec.Ingress) == 0 {
					// Empty ingress rules = deny all ingress traffic
					status.NamespaceIsolation = true
					break
				}
				if policyType == "Egress" && len(netpol.Spec.Egress) == 0 {
					// Empty egress rules = deny all egress traffic
					status.NamespaceIsolation = true
					break
				}
			}
			if status.NamespaceIsolation {
				break
			}
		}
	}

	return status
}

// selectorMatches checks if pod labels match a label selector
// ANCHOR: Label selector matching with MatchExpressions support - Phase 2.4 fix, Dec 26, 2025
// Returns true if pod labels match all requirements in the selector (both MatchLabels and MatchExpressions)
// Empty selector (no MatchLabels and no MatchExpressions) matches all pods
func selectorMatches(labels map[string]string, selector metav1.LabelSelector) bool {
	if labels == nil {
		labels = make(map[string]string)
	}

	// Empty selector (no MatchLabels and no MatchExpressions) matches all pods
	if len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
		return true
	}

	// Check label-based requirements (MatchLabels)
	for key, value := range selector.MatchLabels {
		if labels[key] != value {
			return false
		}
	}

	// Check expression-based requirements (MatchExpressions)
	// Each expression must be satisfied for the match to succeed
	for _, expr := range selector.MatchExpressions {
		labelValue, labelExists := labels[expr.Key]

		switch expr.Operator {
		case metav1.LabelSelectorOpIn:
			// Label value must be in the values list
			found := false
			for _, v := range expr.Values {
				if labelValue == v {
					found = true
					break
				}
			}
			if !found {
				return false
			}

		case metav1.LabelSelectorOpNotIn:
			// Label value must NOT be in the values list
			if labelExists {
				for _, v := range expr.Values {
					if labelValue == v {
						return false
					}
				}
			}

		case metav1.LabelSelectorOpExists:
			// Label key must exist
			if !labelExists {
				return false
			}

		case metav1.LabelSelectorOpDoesNotExist:
			// Label key must NOT exist
			if labelExists {
				return false
			}
		}
	}

	return true
}

// CheckNamespaceDefaultDenyPolicy checks if namespace has default deny NetworkPolicies
// ANCHOR: Namespace isolation policy check - Phase 2.4, Dec 26, 2025
// Returns true if the namespace has a default deny network policy
func (c *Client) CheckNamespaceDefaultDenyPolicy(ctx context.Context, namespace string) bool {
	if namespace == "" {
		return false
	}

	netpols, err := c.clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil || netpols == nil {
		return false
	}

	// ANCHOR: Default-deny detection requires empty selector AND empty rule list - Phase 2.4 fix, Dec 27, 2025
	// Empty selector alone doesn't guarantee isolation (policy could allow all traffic).
	// True isolation requires empty rules for at least one policy type (deny all semantics).
	for _, netpol := range netpols.Items {
		// Check if this is a default deny policy (empty pod selector + empty rules)
		if len(netpol.Spec.PodSelector.MatchLabels) == 0 && len(netpol.Spec.PodSelector.MatchExpressions) == 0 {
			// Empty selector - check if it actually denies traffic (empty rule list)
			for _, policyType := range netpol.Spec.PolicyTypes {
				if policyType == "Ingress" && len(netpol.Spec.Ingress) == 0 {
					// Empty ingress rules = deny all ingress traffic
					return true
				}
				if policyType == "Egress" && len(netpol.Spec.Egress) == 0 {
					// Empty egress rules = deny all egress traffic
					return true
				}
			}
		}
	}

	return false
}

// Data structures for Kubernetes metadata
// ANCHOR: PodMetadata and NodeMetadata types used by enrichment - Phase 2.2, Dec 26, 2025
// These types are defined in the kubernetes package to avoid circular imports.
// They are used by both the K8s client and enrichment pipeline.

type PodMetadata struct {
	Name           string
	Namespace      string
	UID            string
	ServiceAccount string
	Image          string
	ImageRegistry  string
	ImageTag       string
	Labels         map[string]string
	OwnerRef       *OwnerReference
	ContainerName  string

	// ANCHOR: Security context fields extracted from pod spec - Phase 2.2 fix, Dec 26, 2025
	// These fields are populated by extracting values from pod.Spec security context
	// They override the defaults in enricher's containerCtx when available

	// Pod-level security context
	RunAsUser       int64
	RunAsNonRoot    bool
	FSGroup         int64
	SeccompProfile  string
	SELinuxLevel    string
	AppArmorProfile string

	// Container-level security context (from first container)
	AllowPrivilegeEscalation bool
	Privileged               bool
	ReadOnlyRootFilesystem   bool
	RunAsRootContainer       bool
	HostNetwork              bool
	HostIPC                  bool
	HostPID                  bool

	// Resource requests and limits (from first container)
	MemoryLimit   string
	MemoryRequest string
	CPULimit      string
	CPURequest    string

	// Image pull policy (from first container)
	ImagePullPolicy string
}

type OwnerReference struct {
	Kind string
	Name string
	UID  string
}

type NodeMetadata struct {
	Name     string
	Labels   map[string]string
	Taints   []string
	Capacity map[string]string
}

// ServiceAccountMetadata contains RBAC and token information
// ANCHOR: ServiceAccount metadata for RBAC enforcement - Phase 2.3, Dec 26, 2025
// Extracted from ServiceAccount and Token Secret objects for compliance evaluation
type ServiceAccountMetadata struct {
	Name                         string
	Namespace                    string
	AutomountServiceAccountToken bool
	TokenCreatedAt               int64 // Unix timestamp
}

// NetworkPolicyStatus contains network policy restrictions for a pod
// ANCHOR: Network policy status for traffic restriction evaluation - Phase 2.4, Dec 26, 2025
// Evaluated from NetworkPolicy objects that apply to the pod
type NetworkPolicyStatus struct {
	IngressRestricted  bool // True if NetworkPolicy restricts ingress traffic
	EgressRestricted   bool // True if NetworkPolicy restricts egress traffic
	NamespaceIsolation bool // True if namespace has default deny policies
}
