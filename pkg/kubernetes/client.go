// ANCHOR: Kubernetes API client - Dec 26, 2025
// Provides read-only K8s API access for metadata enrichment

package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client provides read-only access to Kubernetes API
type Client struct {
	clientset             *kubernetes.Clientset
	config                *rest.Config
	cache                 *MetadataCache
	apiLimiter            *rate.Limiter
	discoverServerGroups  func() (*metav1.APIGroupList, error)
	listKubeSystemPods    func(ctx context.Context) (*corev1.PodList, error)
	auditMu               sync.RWMutex
	auditMemo             auditLoggingMemo
	rbacMu                sync.RWMutex
	rbacMemo              apiGroupMemo
}

type auditLoggingMemo struct {
	enabled   bool
	checked   bool
	checkedAt time.Time
}

type apiGroupMemo struct {
	enabled   bool
	checked   bool
	checkedAt time.Time
}

const (
	defaultK8sAPIRateLimit = 50
	defaultK8sAPIBurst     = 100
)

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
		apiLimiter: rate.NewLimiter(
			rate.Limit(loadK8sAPIRateLimit()),
			loadK8sAPIBurst(),
		),
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return clientset.Discovery().ServerGroups()
		},
		listKubeSystemPods: func(ctx context.Context) (*corev1.PodList, error) {
			return clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
		},
	}, nil
}

func loadK8sAPIRateLimit() float64 {
	raw := strings.TrimSpace(os.Getenv("OWL_K8S_API_RATE_LIMIT"))
	if raw == "" {
		return defaultK8sAPIRateLimit
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil || parsed <= 0 {
		return defaultK8sAPIRateLimit
	}
	return parsed
}

func loadK8sAPIBurst() int {
	raw := strings.TrimSpace(os.Getenv("OWL_K8S_API_BURST"))
	if raw == "" {
		return defaultK8sAPIBurst
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return defaultK8sAPIBurst
	}
	return parsed
}

func (c *Client) waitForAPIBudget(ctx context.Context) error {
	if c == nil || c.apiLimiter == nil {
		return nil
	}
	return c.apiLimiter.Wait(ctx)
}

// GetClientset returns the underlying Kubernetes clientset
// ANCHOR: Clientset accessor for external API usage - Phase 3.2 Week 3
// Allows other components (like rule engine) to make K8s API calls
// Use this to access the clientset for ConfigMap reads or other K8s operations
func (c *Client) GetClientset() *kubernetes.Clientset {
	return c.clientset
}

// GetCache returns the metadata cache for direct access to cgroup mappings
// ANCHOR: Cache accessor for cgroup fallback lookup - Fix PR-23 #3 /proc race - Mar 25, 2026
// Used by enricher to resolve cgroupID -> pod mappings without K8s API calls
func (c *Client) GetCache() *MetadataCache {
	return c.cache
}

// GetPodMetadata retrieves pod metadata from K8s API
// ANCHOR: Pod metadata query from K8s API - Phase 2.2, Dec 26, 2025
// Retrieves pod name, namespace, UID, service account, image, and labels
func (c *Client) GetPodMetadata(ctx context.Context, namespace, podName string) (*PodMetadata, error) {
	return c.getPodMetadata(ctx, namespace, podName, "")
}

// GetPodMetadataForContainer retrieves pod metadata using a specific container identity.
// ANCHOR: Container-specific metadata extraction - Fix: multi-container context bleed - Mar 29, 2026
// Uses the provided container name to extract security/resource/runtime fields from the
// correct container instead of always using pod.Spec.Containers[0].
func (c *Client) GetPodMetadataForContainer(ctx context.Context, namespace, podName, containerName string) (*PodMetadata, error) {
	return c.getPodMetadata(ctx, namespace, podName, containerName)
}

func (c *Client) getPodMetadata(ctx context.Context, namespace, podName, containerName string) (*PodMetadata, error) {
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("namespace and pod name required")
	}

	// Check cache first
	cacheKey := podName
	if containerName != "" {
		cacheKey = podName + "#" + containerName
	}
	if cached, found := c.cache.GetPod(namespace, cacheKey); found {
		return cached, nil
	}

	// Query K8s API
	if err := c.waitForAPIBudget(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait failed before pod get: %w", err)
	}
	pod, err := c.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}

	// Select container-specific fields from the matched container when available.
	selectedContainer := corev1.Container{}
	selectedContainerName := containerName
	hasSelectedContainer := false
	if containerName != "" {
		for _, container := range pod.Spec.Containers {
			if container.Name == containerName {
				selectedContainer = container
				selectedContainerName = container.Name
				hasSelectedContainer = true
				break
			}
		}
	}
	if !hasSelectedContainer && len(pod.Spec.Containers) > 0 {
		selectedContainer = pod.Spec.Containers[0]
		selectedContainerName = selectedContainer.Name
		hasSelectedContainer = true
	}

	// Extract metadata from selected pod container.
	image := ""
	imagePullPolicy := "IfNotPresent"
	if hasSelectedContainer {
		image = selectedContainer.Image
		if selectedContainer.ImagePullPolicy != "" {
			imagePullPolicy = string(selectedContainer.ImagePullPolicy)
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
	var memoryLimit, memoryRequest, cpuLimit, cpuRequest, storageRequest string

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

	// AppArmor profile from pod annotations
	// ANCHOR: Extract AppArmor profile with container name in annotation key - Phase 2.2 fix, Dec 26, 2025
	// K8s annotation key includes container name suffix, e.g. container.apparmor.security.beta.kubernetes.io/{container_name}
	if pod.Annotations != nil && selectedContainerName != "" {
		apparmorProfile = pod.Annotations["container.apparmor.security.beta.kubernetes.io/"+selectedContainerName]
	}

	// Container-level security context (from selected container)
	// ANCHOR: Extract container-level RunAsNonRoot to override pod-level setting - Phase 2.2 fix, Dec 26, 2025
	// Container-level security context takes precedence over pod-level for runAsNonRoot
	if hasSelectedContainer {
		container := selectedContainer
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
			if storage, ok := container.Resources.Requests["ephemeral-storage"]; ok {
				storageRequest = storage.String()
			}
		}
	}

	// ANCHOR: Compliance field extraction for pod metadata - Feature: image/volume/kernel signals - Mar 22, 2026
	// Derives CIS inputs from annotations, imagePullSecrets, volume mounts, and sysctls.
	serviceAccountName := pod.Spec.ServiceAccountName
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}

	var serviceAccount *corev1.ServiceAccount
	if c.clientset != nil && serviceAccountName != "" {
		if err := c.waitForAPIBudget(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait failed before serviceaccount get: %w", err)
		}
		if sa, err := c.clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, serviceAccountName, metav1.GetOptions{}); err == nil {
			serviceAccount = sa
		}
	}

	imageScanStatus := ImageScanStatusFromPod(pod, selectedContainerName)
	imageSigned := false
	if signed, ok := ImageSignedFromPod(pod, selectedContainerName); ok {
		imageSigned = signed
	}
	imageRegistryAuth := ImageRegistryAuthFromPod(pod, selectedContainerName, serviceAccount)
	runtime := ContainerRuntimeFromPod(pod, selectedContainerName)
	tokenTTL := ServiceAccountTokenTTLFromPod(pod)
	isolationLevel := 0
	volumeType := ""
	if hasSelectedContainer {
		volumeType = VolumeTypeForContainer(pod, selectedContainer)
		isolationLevel = IsolationLevelForContainer(pod, selectedContainer)
	}
	kernelHardening := KernelHardeningFromPod(pod)
	auditLoggingEnabled, hasAuditOverride := AuditLoggingEnabledFromPod(pod)
	if !hasAuditOverride {
		auditLoggingEnabled = c.IsAuditLoggingEnabled(ctx)
	}
	var ownerRef *OwnerReference
	if len(pod.OwnerReferences) > 0 {
		owner := pod.OwnerReferences[0]
		ownerRef = &OwnerReference{
			Kind: owner.Kind,
			Name: owner.Name,
			UID:  string(owner.UID),
		}
	}

	// Create PodMetadata with extracted security context
	metadata := &PodMetadata{
		Name:                     pod.Name,
		Namespace:                pod.Namespace,
		UID:                      string(pod.UID),
		ServiceAccount:           serviceAccountName,
		Image:                    image,
		ImageRegistry:            "", // Will be parsed by enricher
		ImageTag:                 "", // Will be parsed by enricher
		Labels:                   pod.Labels,
		OwnerRef:                 ownerRef,
		ContainerName:            selectedContainerName,
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
		// ANCHOR: Compliance signal fields from pod spec - Feature: image/volume/kernel signals - Mar 22, 2026
		// Populate CIS fields from annotations, imagePullSecrets, volumes, and sysctls.
		ImageScanStatus:               imageScanStatus,
		ImageRegistryAuth:             imageRegistryAuth,
		ImageSigned:                   imageSigned,
		StorageRequest:                storageRequest,
		VolumeType:                    volumeType,
		Runtime:                       runtime,
		ServiceAccountTokenTTLSeconds: tokenTTL,
		IsolationLevel:                isolationLevel,
		KernelHardening:               kernelHardening,
		AuditLoggingEnabled:           auditLoggingEnabled,
	}

	// Store in cache
	c.cache.SetPod(namespace, cacheKey, metadata)

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
		namespace, podName, containerName, ok := parseNamespacedPodContainerMapping(mapping)
		if ok {
			return c.GetPodMetadataForContainer(ctx, namespace, podName, containerName)
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

	// Prefer a node-scoped all-namespace list to avoid sequential namespace+cluster-wide scans.
	if nodeName := strings.TrimSpace(os.Getenv("OWL_NODE_NAME")); nodeName != "" {
		if err := c.waitForAPIBudget(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait failed before node-scoped pod list: %w", err)
		}
		nodePods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err == nil {
			for _, pod := range nodePods.Items {
				matchedContainer, found := findContainerNameForID(c, pod, normalizedID)
				if found {
					mapping := formatNamespacedPodContainerMapping(pod.Namespace, pod.Name, matchedContainer)
					c.cache.SetContainerMapping(containerID, mapping)
					return c.GetPodMetadataForContainer(ctx, pod.Namespace, pod.Name, matchedContainer)
				}
			}
		}
	}

	// Fall back to namespace-scoped lookup.
	var agentListErr error
	if agentNamespace != "" {
		if err := c.waitForAPIBudget(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait failed before namespace pod list: %w", err)
		}
		pods, err := c.clientset.CoreV1().Pods(agentNamespace).List(ctx, metav1.ListOptions{})
		agentListErr = err
		if err == nil {
			for _, pod := range pods.Items {
				matchedContainer, found := findContainerNameForID(c, pod, normalizedID)
				if found {
					mapping := formatNamespacedPodContainerMapping(pod.Namespace, pod.Name, matchedContainer)
					c.cache.SetContainerMapping(containerID, mapping)
					return c.GetPodMetadataForContainer(ctx, pod.Namespace, pod.Name, matchedContainer)
				}
			}
		}
	}

	// Final fallback: cluster-wide list.
	if err := c.waitForAPIBudget(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait failed before cluster-wide pod list: %w", err)
	}
	allPods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		if agentListErr != nil {
			return nil, fmt.Errorf("failed to list pods in agent namespace %q: %v; cluster-wide list failed: %w", agentNamespace, agentListErr, err)
		}
		return nil, fmt.Errorf("failed to list pods cluster-wide: %w", err)
	}

	for _, pod := range allPods.Items {
		matchedContainer, found := findContainerNameForID(c, pod, normalizedID)
		if found {
			mapping := formatNamespacedPodContainerMapping(pod.Namespace, pod.Name, matchedContainer)
			c.cache.SetContainerMapping(containerID, mapping)
			return c.GetPodMetadataForContainer(ctx, pod.Namespace, pod.Name, matchedContainer)
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

func formatNamespacedPodContainerMapping(namespace, podName, containerName string) string {
	if containerName == "" {
		return fmt.Sprintf("%s/%s", namespace, podName)
	}
	return fmt.Sprintf("%s/%s/%s", namespace, podName, containerName)
}

func parseNamespacedPodContainerMapping(mapping string) (namespace, podName, containerName string, ok bool) {
	parts := strings.SplitN(mapping, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	container := ""
	if len(parts) == 3 {
		container = parts[2]
	}
	return parts[0], parts[1], container, true
}

func findContainerNameForID(c *Client, pod corev1.Pod, normalizedID string) (string, bool) {
	for _, status := range pod.Status.ContainerStatuses {
		if c.normalizeContainerID(status.ContainerID) == normalizedID {
			return status.Name, true
		}
	}
	for _, status := range pod.Status.InitContainerStatuses {
		if c.normalizeContainerID(status.ContainerID) == normalizedID {
			return status.Name, true
		}
	}
	for _, status := range pod.Status.EphemeralContainerStatuses {
		if c.normalizeContainerID(status.ContainerID) == normalizedID {
			return status.Name, true
		}
	}
	return "", false
}

const auditLoggingCacheTTL = 5 * time.Minute
const rbacAPICacheTTL = 10 * time.Minute
const wildcardVerbWeight = 100

// IsRBACAPIEnabled returns whether the RBAC API group is available.
// ANCHOR: RBAC API capability detection - Fix: RBACEnforced always true - Mar 29, 2026
// Uses discovery groups with memoized TTL to avoid per-event API discovery calls.
func (c *Client) IsRBACAPIEnabled(ctx context.Context) bool {
	if c == nil || (c.clientset == nil && c.discoverServerGroups == nil) {
		return false
	}

	c.rbacMu.RLock()
	if c.rbacMemo.checked && time.Since(c.rbacMemo.checkedAt) < rbacAPICacheTTL {
		enabled := c.rbacMemo.enabled
		c.rbacMu.RUnlock()
		return enabled
	}
	c.rbacMu.RUnlock()

	c.rbacMu.Lock()
	defer c.rbacMu.Unlock()

	if c.rbacMemo.checked && time.Since(c.rbacMemo.checkedAt) < rbacAPICacheTTL {
		return c.rbacMemo.enabled
	}

	if err := c.waitForAPIBudget(ctx); err != nil {
		if c.rbacMemo.checked {
			return c.rbacMemo.enabled
		}
		// Fail-open on transient discovery budget errors until first successful probe.
		return true
	}
	groups, err := c.serverGroups()
	if err != nil {
		if c.rbacMemo.checked {
			return c.rbacMemo.enabled
		}
		// Fail-open on transient discovery errors until first successful probe.
		return true
	}

	enabled := hasAPIGroup(groups, "rbac.authorization.k8s.io")
	c.rbacMemo = apiGroupMemo{
		enabled:   enabled,
		checked:   true,
		checkedAt: time.Now(),
	}
	return enabled
}

func (c *Client) serverGroups() (*metav1.APIGroupList, error) {
	if c == nil {
		return nil, fmt.Errorf("kubernetes client is nil")
	}
	if c.discoverServerGroups != nil {
		return c.discoverServerGroups()
	}
	if c.clientset == nil {
		return nil, fmt.Errorf("kubernetes clientset not configured")
	}
	return c.clientset.Discovery().ServerGroups()
}

func hasAPIGroup(groups *metav1.APIGroupList, target string) bool {
	if groups == nil || target == "" {
		return false
	}
	for _, group := range groups.Groups {
		if group.Name == target {
			return true
		}
	}
	return false
}

// IsAuditLoggingEnabled returns best-effort cluster audit logging status.
// ANCHOR: Audit logging status detection - Feature: CIS_5.5.1 inputs - Mar 29, 2026
// Uses kube-apiserver pod command/args flags with short TTL caching.
func (c *Client) IsAuditLoggingEnabled(ctx context.Context) bool {
	if c == nil || (c.clientset == nil && c.listKubeSystemPods == nil) {
		return false
	}

	c.auditMu.RLock()
	if c.auditMemo.checked && time.Since(c.auditMemo.checkedAt) < auditLoggingCacheTTL {
		enabled := c.auditMemo.enabled
		c.auditMu.RUnlock()
		return enabled
	}
	c.auditMu.RUnlock()

	c.auditMu.Lock()
	defer c.auditMu.Unlock()

	if c.auditMemo.checked && time.Since(c.auditMemo.checkedAt) < auditLoggingCacheTTL {
		return c.auditMemo.enabled
	}

	enabled, ok := c.detectAuditLoggingEnabled(ctx)
	if !ok {
		if c.auditMemo.checked {
			return c.auditMemo.enabled
		}
		// Unknown audit status should not auto-pass CIS 5.5.1 checks.
		c.auditMemo = auditLoggingMemo{
			enabled:   false,
			checked:   true,
			checkedAt: time.Now(),
		}
		return false
	}
	c.auditMemo = auditLoggingMemo{
		enabled:   enabled,
		checked:   true,
		checkedAt: time.Now(),
	}
	return enabled
}

func (c *Client) detectAuditLoggingEnabled(ctx context.Context) (bool, bool) {
	if err := c.waitForAPIBudget(ctx); err != nil {
		return false, false
	}
	pods, err := c.kubeSystemPods(ctx)
	if err != nil {
		return false, false
	}

	sawAPIServer := false
	for _, pod := range pods.Items {
		if !isAPIServerPod(pod) {
			continue
		}
		sawAPIServer = true
		for _, container := range pod.Spec.Containers {
			if hasAuditFlags(container.Command, container.Args) {
				return true, true
			}
		}
	}
	if !sawAPIServer {
		return false, false
	}
	return false, true
}

func (c *Client) kubeSystemPods(ctx context.Context) (*corev1.PodList, error) {
	if c == nil {
		return nil, fmt.Errorf("kubernetes client is nil")
	}
	if c.listKubeSystemPods != nil {
		return c.listKubeSystemPods(ctx)
	}
	if c.clientset == nil {
		return nil, fmt.Errorf("kubernetes clientset not configured")
	}
	return c.clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
}

func isAPIServerPod(pod corev1.Pod) bool {
	if strings.Contains(pod.Name, "kube-apiserver") {
		return true
	}
	if pod.Labels == nil {
		return false
	}
	if pod.Labels["component"] == "kube-apiserver" {
		return true
	}
	if pod.Labels["k8s-app"] == "kube-apiserver" {
		return true
	}
	return false
}

func hasAuditFlags(command, args []string) bool {
	joined := strings.Join(append(append([]string{}, command...), args...), " ")
	return strings.Contains(joined, "--audit-log-path") ||
		strings.Contains(joined, "--audit-policy-file") ||
		strings.Contains(joined, "--audit-webhook-config-file")
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
	if err := c.waitForAPIBudget(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait failed before node get: %w", err)
	}
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
	if err := c.waitForAPIBudget(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait failed before serviceaccount metadata get: %w", err)
	}
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
		if err := c.waitForAPIBudget(ctx); err != nil {
			return metadata, nil
		}
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
		return 1 // Default to standard when identity is unavailable
	}

	return permissionLevelFromCount(c.CountRBACPermissions(ctx, namespace, saName))
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
	if err := c.waitForAPIBudget(ctx); err != nil {
		return 0
	}
	rbs, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, rb := range rbs.Items {
			for _, subject := range rb.Subjects {
				if !rbacSubjectMatchesServiceAccount(subject, namespace, saName) {
					continue
				}

				switch rb.RoleRef.Kind {
				case "Role":
					if err := c.waitForAPIBudget(ctx); err != nil {
						continue
					}
					role, err := c.clientset.RbacV1().Roles(namespace).Get(ctx, rb.RoleRef.Name, metav1.GetOptions{})
					if err != nil {
						continue
					}
					totalPermissions += countPolicyRulesPermissions(role.Rules)
				case "ClusterRole":
					if err := c.waitForAPIBudget(ctx); err != nil {
						continue
					}
					role, err := c.clientset.RbacV1().ClusterRoles().Get(ctx, rb.RoleRef.Name, metav1.GetOptions{})
					if err != nil {
						continue
					}
					totalPermissions += countPolicyRulesPermissions(role.Rules)
				}
			}
		}
	}

	// Check ClusterRoleBindings
	if err := c.waitForAPIBudget(ctx); err != nil {
		return totalPermissions
	}
	crbs, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range crbs.Items {
			for _, subject := range crb.Subjects {
				if !rbacSubjectMatchesServiceAccount(subject, namespace, saName) {
					continue
				}

				switch crb.RoleRef.Kind {
				case "ClusterRole":
					if err := c.waitForAPIBudget(ctx); err != nil {
						continue
					}
					crole, err := c.clientset.RbacV1().ClusterRoles().Get(ctx, crb.RoleRef.Name, metav1.GetOptions{})
					if err != nil {
						continue
					}
					totalPermissions += countPolicyRulesPermissions(crole.Rules)
				case "Role":
					if err := c.waitForAPIBudget(ctx); err != nil {
						continue
					}
					role, err := c.clientset.RbacV1().Roles(namespace).Get(ctx, crb.RoleRef.Name, metav1.GetOptions{})
					if err != nil {
						continue
					}
					totalPermissions += countPolicyRulesPermissions(role.Rules)
				}
			}
		}
	}

	return totalPermissions
}

// CountBoundRoles returns the number of distinct Role/ClusterRole refs bound to the service account.
func (c *Client) CountBoundRoles(ctx context.Context, namespace, saName string) int {
	if namespace == "" || saName == "" {
		return 0
	}

	refs := make(map[string]struct{})

	if err := c.waitForAPIBudget(ctx); err != nil {
		return 0
	}
	rbs, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, rb := range rbs.Items {
			for _, subject := range rb.Subjects {
				if !rbacSubjectMatchesServiceAccount(subject, namespace, saName) {
					continue
				}
				if rb.RoleRef.Name == "" {
					continue
				}
				refKey := rb.RoleRef.Kind + "/" + rb.RoleRef.Name
				refs[refKey] = struct{}{}
				break
			}
		}
	}

	if err := c.waitForAPIBudget(ctx); err != nil {
		return len(refs)
	}
	crbs, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range crbs.Items {
			for _, subject := range crb.Subjects {
				if !rbacSubjectMatchesServiceAccount(subject, namespace, saName) {
					continue
				}
				if crb.RoleRef.Name == "" {
					continue
				}
				refKey := crb.RoleRef.Kind + "/" + crb.RoleRef.Name
				refs[refKey] = struct{}{}
				break
			}
		}
	}

	return len(refs)
}

// HasRBACPolicy returns whether the service account is referenced by any RBAC binding.
func (c *Client) HasRBACPolicy(ctx context.Context, namespace, saName string) bool {
	return c.CountBoundRoles(ctx, namespace, saName) > 0
}

// MaxRolePermissionCount returns the highest permission count among roles bound to a service account.
// This is used for role granularity checks (broadest bound role), distinct from total permissions.
func (c *Client) MaxRolePermissionCount(ctx context.Context, namespace, saName string) int {
	if namespace == "" || saName == "" {
		return 0
	}

	permissionByRef := make(map[string]int)

	if err := c.waitForAPIBudget(ctx); err != nil {
		return 0
	}
	rbs, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, rb := range rbs.Items {
			for _, subject := range rb.Subjects {
				if !rbacSubjectMatchesServiceAccount(subject, namespace, saName) {
					continue
				}
				if rb.RoleRef.Name == "" {
					continue
				}
				refKey := rb.RoleRef.Kind + "/" + rb.RoleRef.Name
				if _, exists := permissionByRef[refKey]; exists {
					continue
				}
				permissionByRef[refKey] = c.roleRefPermissionCount(ctx, namespace, rb.RoleRef.Kind, rb.RoleRef.Name)
			}
		}
	}

	if err := c.waitForAPIBudget(ctx); err != nil {
		return maxPermissionCount(permissionByRef)
	}
	crbs, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range crbs.Items {
			for _, subject := range crb.Subjects {
				if !rbacSubjectMatchesServiceAccount(subject, namespace, saName) {
					continue
				}
				if crb.RoleRef.Name == "" {
					continue
				}
				refKey := crb.RoleRef.Kind + "/" + crb.RoleRef.Name
				if _, exists := permissionByRef[refKey]; exists {
					continue
				}
				permissionByRef[refKey] = c.roleRefPermissionCount(ctx, namespace, crb.RoleRef.Kind, crb.RoleRef.Name)
			}
		}
	}

	return maxPermissionCount(permissionByRef)
}

func (c *Client) roleRefPermissionCount(ctx context.Context, namespace, roleKind, roleName string) int {
	if roleName == "" {
		return 0
	}

	switch roleKind {
	case "Role":
		if err := c.waitForAPIBudget(ctx); err != nil {
			return 0
		}
		role, err := c.clientset.RbacV1().Roles(namespace).Get(ctx, roleName, metav1.GetOptions{})
		if err != nil {
			return 0
		}
		return countPolicyRulesPermissions(role.Rules)
	case "ClusterRole":
		if err := c.waitForAPIBudget(ctx); err != nil {
			return 0
		}
		role, err := c.clientset.RbacV1().ClusterRoles().Get(ctx, roleName, metav1.GetOptions{})
		if err != nil {
			return 0
		}
		return countPolicyRulesPermissions(role.Rules)
	default:
		return 0
	}
}

func maxPermissionCount(permissionByRef map[string]int) int {
	maxPermissions := 0
	for _, permissions := range permissionByRef {
		if permissions > maxPermissions {
			maxPermissions = permissions
		}
	}
	return maxPermissions
}

func rbacSubjectMatchesServiceAccount(subject rbacv1.Subject, namespace, saName string) bool {
	if subject.Kind != "ServiceAccount" || subject.Name != saName {
		return false
	}

	// ClusterRoleBinding subjects may legitimately omit namespace; treat empty as match.
	if subject.Namespace == "" {
		return true
	}
	return subject.Namespace == namespace
}

func permissionLevelFromCount(permissionCount int) int {
	switch {
	case permissionCount <= 0:
		return 0
	case permissionCount <= 10:
		return 1
	case permissionCount <= 100:
		return 2
	default:
		return 3
	}
}

func countPolicyRulesPermissions(rules []rbacv1.PolicyRule) int {
	total := 0
	for _, rule := range rules {
		total += countPolicyRulePermissions(rule)
	}
	return total
}

func countPolicyRulePermissions(rule rbacv1.PolicyRule) int {
	verbSet := make(map[string]struct{}, len(rule.Verbs))
	for _, verb := range rule.Verbs {
		if strings.TrimSpace(verb) == "" {
			continue
		}
		verbSet[verb] = struct{}{}
	}
	if len(verbSet) == 0 {
		return 0
	}
	if _, hasWildcard := verbSet["*"]; hasWildcard {
		return wildcardVerbWeight
	}
	return len(verbSet)
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
	if err := c.waitForAPIBudget(ctx); err != nil {
		return status
	}
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

	if err := c.waitForAPIBudget(ctx); err != nil {
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

// ListAllPods returns a map of all pods across all namespaces with their metadata.
// ANCHOR: List all pods for cgroup pre-caching - Fix PR-23 #3 /proc race - Mar 25, 2026
// Returns map with key "namespace/podname" for easy lookup of pod by identifier.
// Used at enricher startup to pre-populate container ID to pod mappings.
// Fails gracefully if K8s API is unavailable (returns empty map with error).
func (c *Client) ListAllPods(ctx context.Context) (map[string]*PodMetadata, error) {
	if err := c.waitForAPIBudget(ctx); err != nil {
		return make(map[string]*PodMetadata), err
	}
	podList, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return make(map[string]*PodMetadata), err
	}

	result := make(map[string]*PodMetadata)
	for _, pod := range podList.Items {
		// Extract metadata for each pod
		podMeta := &PodMetadata{
			Name:              pod.Name,
			Namespace:         pod.Namespace,
			UID:               string(pod.UID),
			ServiceAccount:    pod.Spec.ServiceAccountName,
			Labels:            pod.Labels,
			ContainerIDToName: make(map[string]string),
		}

		// ANCHOR: All-container ID extraction for multi-container mapping - Fix PR-23 #6 - Mar 26, 2026
		// Iterate ContainerStatuses, InitContainerStatuses, EphemeralContainerStatuses to collect
		// all container IDs so sidecars and init containers get cgroup→pod mappings registered.
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.ContainerID == "" {
				continue
			}
			parts := strings.Split(cs.ContainerID, "://")
			id := cs.ContainerID
			if len(parts) == 2 {
				id = parts[1]
			}
			podMeta.ContainerIDs = append(podMeta.ContainerIDs, id)
			podMeta.ContainerIDToName[id] = cs.Name
		}
		for _, cs := range pod.Status.InitContainerStatuses {
			if cs.ContainerID == "" {
				continue
			}
			parts := strings.Split(cs.ContainerID, "://")
			id := cs.ContainerID
			if len(parts) == 2 {
				id = parts[1]
			}
			podMeta.ContainerIDs = append(podMeta.ContainerIDs, id)
			podMeta.ContainerIDToName[id] = cs.Name
		}
		for _, cs := range pod.Status.EphemeralContainerStatuses {
			if cs.ContainerID == "" {
				continue
			}
			parts := strings.Split(cs.ContainerID, "://")
			id := cs.ContainerID
			if len(parts) == 2 {
				id = parts[1]
			}
			podMeta.ContainerIDs = append(podMeta.ContainerIDs, id)
			podMeta.ContainerIDToName[id] = cs.Name
		}

		// Keep ContainerID/ContainerName/Image from first main container for backward compat
		if len(pod.Status.ContainerStatuses) > 0 {
			cs := pod.Status.ContainerStatuses[0]
			podMeta.Image = cs.ImageID
			podMeta.ContainerName = cs.Name

			// Extract container ID from containerID string (format: docker://xyz or containerd://xyz)
			if cs.ContainerID != "" {
				parts := strings.Split(cs.ContainerID, "://")
				if len(parts) == 2 {
					podMeta.ContainerID = parts[1]
				} else {
					podMeta.ContainerID = cs.ContainerID
				}
			}
		}

		key := pod.Namespace + "/" + pod.Name
		result[key] = podMeta
	}

	return result, nil
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

	// ANCHOR: Container and cgroup ID fields for cgroup mapping - Fix PR-23 #3 /proc race - Mar 25, 2026
	// ContainerID extracted from pod container status (e.g., docker://xyz or containerd://xyz)
	// CgroupID captured from kernel for race-free pod resolution when /proc fails
	ContainerID string
	CgroupID    uint64
	// ANCHOR: All container IDs for multi-container pod mapping - Fix PR-23 #6 - Mar 26, 2026
	// Includes IDs from ContainerStatuses, InitContainerStatuses, EphemeralContainerStatuses.
	// Used by refreshCgroupPodMappings to register cgroup mappings for all containers.
	ContainerIDs []string
	// ContainerIDToName maps normalized container IDs to container names in this pod.
	ContainerIDToName map[string]string

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

	// Container-level security context (from selected/matched container)
	AllowPrivilegeEscalation bool
	Privileged               bool
	ReadOnlyRootFilesystem   bool
	RunAsRootContainer       bool
	HostNetwork              bool
	HostIPC                  bool
	HostPID                  bool

	// Resource requests and limits (from selected/matched container)
	MemoryLimit    string
	MemoryRequest  string
	CPULimit       string
	CPURequest     string
	StorageRequest string

	// Image pull policy (from selected/matched container)
	ImagePullPolicy string

	// ANCHOR: Compliance signal fields for CIS controls - Mar 22, 2026
	// Fields populated from annotations, imagePullSecrets, volume mounts, and sysctls.
	ImageScanStatus               string
	ImageRegistryAuth             bool
	ImageSigned                   bool
	VolumeType                    string
	Runtime                       string
	ServiceAccountTokenTTLSeconds int64
	IsolationLevel                int
	KernelHardening               bool
	AuditLoggingEnabled           bool
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
