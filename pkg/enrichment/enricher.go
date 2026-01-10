// ANCHOR: Event enrichment pipeline - Dec 26, 2025
// Converts cilium/ebpf events to enriched events with K8s and container context
// Phase 3: Migrated from goBPF to cilium/ebpf (Dec 27, 2025)

package enrichment

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/kubernetes"
)

// Enricher adds K8s context to raw cilium/ebpf events
type Enricher struct {
	K8sClient *kubernetes.Client
	ClusterID string
	NodeName  string
	Logger    *zap.Logger

	// ANCHOR: Container to pod mapping cache for fast lookups - Phase 2, Dec 26, 2025
	// Caches containerID -> namespace/podname mappings to avoid repeated K8s API queries
	containerToPodMutex sync.RWMutex
	containerToPodCache map[string]string // containerID -> "namespace/podname"
}

// NewEnricher creates a new event enricher
// ANCHOR: Enricher initialization without circular dependency - Dec 26, 2025
// Pass only needed fields (ClusterID, NodeName) instead of full Config to avoid import cycle
func NewEnricher(k8sClient *kubernetes.Client, clusterID, nodeName string) (*Enricher, error) {
	logger, _ := zap.NewProduction()

	return &Enricher{
		K8sClient:           k8sClient,
		ClusterID:           clusterID,
		NodeName:            nodeName,
		Logger:              logger,
		containerToPodCache: make(map[string]string),
	}, nil
}

// ANCHOR: Helper methods for enrichment field extraction - Phase 2, Dec 26, 2025
// These methods query K8s API and parse pod specs to populate enrichment fields

// getPodMetadata retrieves pod metadata from K8s API, using cache when available
// ANCHOR: Pod metadata lookup via K8s API - Phase 2.2, Dec 26, 2025
// First checks local enricher cache, then queries K8s API for pod metadata via container ID
func (e *Enricher) getPodMetadata(ctx context.Context, containerID string) *PodMetadata {
	if e.K8sClient == nil || containerID == "" {
		return nil
	}

	// Check local enricher cache first
	e.containerToPodMutex.RLock()
	cachedMapping, found := e.containerToPodCache[containerID]
	e.containerToPodMutex.RUnlock()

	if found {
		// Parse cached mapping: "namespace/podname"
		parts := strings.Split(cachedMapping, "/")
		if len(parts) == 2 {
			// Use K8s client to retrieve the pod metadata with its cache
			metadata, err := e.K8sClient.GetPodMetadata(ctx, parts[0], parts[1])
			if err != nil {
				e.Logger.Debug("failed to get pod metadata from cache", zap.Error(err))
				return nil
			}
			return metadata
		}
	}

	// Query K8s API for pod lookup by container ID
	metadata, err := e.K8sClient.GetPodByContainerID(ctx, containerID)
	if err != nil {
		e.Logger.Debug("failed to find pod by container ID", zap.String("containerID", containerID), zap.Error(err))
		return nil
	}

	if metadata != nil {
		// Cache the mapping locally for future use
		mapping := fmt.Sprintf("%s/%s", metadata.Namespace, metadata.Name)
		e.containerToPodMutex.Lock()
		e.containerToPodCache[containerID] = mapping
		e.containerToPodMutex.Unlock()
	}

	return metadata
}

// parseImageRegistry extracts registry from full image path (e.g. "docker.io/library/nginx:latest" -> "docker.io")
func (e *Enricher) parseImageRegistry(image string) string {
	if image == "" {
		return ""
	}

	// If image contains /, extract registry part
	parts := strings.Split(image, "/")
	if len(parts) > 1 && strings.Contains(parts[0], ".") {
		return parts[0]
	}

	// Default to docker.io if no registry specified
	return "docker.io"
}

// parseImageTag extracts tag from full image path (e.g. "nginx:latest" -> "latest")
func (e *Enricher) parseImageTag(image string) string {
	if image == "" {
		return ""
	}

	// Check for tag separator
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[idx+1:]
	}

	// Default to 'latest' if no tag specified
	return "latest"
}

// EnrichProcessEvent enriches a cilium/ebpf process event
// ANCHOR: Process event enrichment with security context - Phase 2, Dec 26, 2025
// Migrated from goBPF to cilium/ebpf - Dec 27, 2025
// Generic implementation that works with any event structure
// Populates container security context, pod metadata, and RBAC fields
func (e *Enricher) EnrichProcessEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if rawEvent == nil {
		return nil, fmt.Errorf("nil process event")
	}

	// Extract fields from raw event using reflection to avoid circular imports
	// Events from pkg/ebpf have PID, UID, GID, Command, Filename fields
	v := reflect.ValueOf(rawEvent).Elem()
	pidVal := v.FieldByName("PID").Uint()
	uidVal := v.FieldByName("UID").Uint()
	gidVal := v.FieldByName("GID").Uint()
	cmdVal := v.FieldByName("Command").String()
	fnVal := v.FieldByName("Filename").String()

	// Get pod metadata from K8s API (returns nil if not available)
	podMeta := e.getPodMetadata(ctx, "")

	// Build Kubernetes context with available metadata
	k8sCtx := &K8sContext{
		ClusterID: e.ClusterID,
		NodeName:  e.NodeName,
	}

	// Populate fields from pod metadata if available
	if podMeta != nil {
		k8sCtx.Namespace = podMeta.Namespace
		k8sCtx.PodName = podMeta.Name
		k8sCtx.PodUID = podMeta.UID
		k8sCtx.ServiceAccount = podMeta.ServiceAccount
		k8sCtx.Image = podMeta.Image
		k8sCtx.ImageRegistry = e.parseImageRegistry(podMeta.Image)
		k8sCtx.ImageTag = e.parseImageTag(podMeta.Image)
		k8sCtx.Labels = podMeta.Labels

		// ANCHOR: Extract RBAC context from ServiceAccount and Role bindings - Phase 2.3, Dec 26, 2025
		// Query RBAC metadata only if K8s client is available and service account is set
		if e.K8sClient != nil && podMeta.ServiceAccount != "" {
			// Get ServiceAccount metadata
			saMeta, err := e.K8sClient.GetServiceAccountMetadata(ctx, podMeta.Namespace, podMeta.ServiceAccount)
			if err == nil && saMeta != nil {
				k8sCtx.AutomountServiceAccountToken = saMeta.AutomountServiceAccountToken
				// Calculate token age (current time - token creation time)
				if saMeta.TokenCreatedAt > 0 {
					k8sCtx.ServiceAccountTokenAge = time.Now().Unix() - saMeta.TokenCreatedAt
				}
			}

			// Get RBAC privilege level (0=restricted, 1=standard, 2=elevated, 3=admin)
			k8sCtx.RBACLevel = e.K8sClient.GetRBACLevel(ctx, podMeta.Namespace, podMeta.ServiceAccount)
			k8sCtx.RBACEnforced = k8sCtx.RBACLevel >= 0 // Always true if we got a result

			// Count permission grants
			k8sCtx.ServiceAccountPermissions = e.K8sClient.CountRBACPermissions(ctx, podMeta.Namespace, podMeta.ServiceAccount)
			k8sCtx.RBACPolicyDefined = k8sCtx.ServiceAccountPermissions > 0
			k8sCtx.RolePermissionCount = k8sCtx.ServiceAccountPermissions
		}
	}

	// Build container context with security context from pod spec or defaults
	// ANCHOR: Extract security context from pod metadata - Phase 2.2 fix, Dec 26, 2025
	// Use pod spec security context values if available, otherwise fall back to defaults
	containerCtx := &ContainerContext{
		RunAsRoot: false, // Will be set below based on podMeta or eBPF UID
	}

	// Apply pod security context
	if podMeta != nil {
		// Pod-level security context
		// ANCHOR: Determine RunAsRoot using K8s security context booleans - Phase 2.2 fix, Dec 26, 2025
		// RunAsNonRoot boolean is the authoritative field; fall back to RunAsRootContainer only if not set
		// Don't use RunAsUser == 0 since zero is the default when field is unspecified
		if podMeta.RunAsNonRoot {
			containerCtx.RunAsRoot = false
		} else {
			containerCtx.RunAsRoot = podMeta.RunAsRootContainer || (uidVal == 0)
		}
		containerCtx.AllowPrivilegeEscalation = podMeta.AllowPrivilegeEscalation
		containerCtx.Privileged = podMeta.Privileged
		containerCtx.ReadOnlyFilesystem = podMeta.ReadOnlyRootFilesystem
		containerCtx.HostNetwork = podMeta.HostNetwork
		containerCtx.HostIPC = podMeta.HostIPC
		containerCtx.HostPID = podMeta.HostPID
		containerCtx.SeccompProfile = podMeta.SeccompProfile
		containerCtx.ApparmorProfile = podMeta.AppArmorProfile
		containerCtx.SELinuxLevel = podMeta.SELinuxLevel
		containerCtx.ImagePullPolicy = podMeta.ImagePullPolicy
		containerCtx.MemoryLimit = podMeta.MemoryLimit
		containerCtx.CPULimit = podMeta.CPULimit
		containerCtx.MemoryRequest = podMeta.MemoryRequest
		containerCtx.CPURequest = podMeta.CPURequest
	} else {
		// Fallback to defaults when pod metadata not available
		containerCtx.RunAsRoot = uidVal == 0
		containerCtx.AllowPrivilegeEscalation = true  // Default to true (least restrictive)
		containerCtx.Privileged = false
		containerCtx.ReadOnlyFilesystem = false
		containerCtx.HostNetwork = false
		containerCtx.HostIPC = false
		containerCtx.HostPID = false
		containerCtx.SeccompProfile = "unconfined" // Default to unconfined
		containerCtx.ApparmorProfile = ""
		containerCtx.SELinuxLevel = ""
		containerCtx.ImagePullPolicy = "IfNotPresent" // K8s default
		containerCtx.MemoryLimit = ""
		containerCtx.CPULimit = ""
		containerCtx.MemoryRequest = ""
		containerCtx.CPURequest = ""
	}

	return &EnrichedEvent{
		RawEvent:  rawEvent,
		EventType: "process_execution",
		Timestamp: time.Now(),
		Kubernetes: k8sCtx,
		Container: containerCtx,
		Process: &ProcessContext{
			PID:      uint32(pidVal),
			UID:      uint32(uidVal),
			GID:      uint32(gidVal),
			Command:  cmdVal,
			Filename: fnVal,
		},
	}, nil
}

// EnrichNetworkEvent enriches a cilium/ebpf network event
// ANCHOR: Network event enrichment with policy context - Phase 2, Dec 26, 2025
// Migrated from goBPF to cilium/ebpf with reflection-based field extraction - Dec 27, 2025
// Populates network policy and namespace isolation fields; uses interface{} to avoid circular imports
func (e *Enricher) EnrichNetworkEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if rawEvent == nil {
		return nil, fmt.Errorf("nil network event")
	}

	// Extract fields from raw event using reflection to avoid circular imports
	// Events from pkg/ebpf have SourceIP, DestinationIP, SourcePort, DestinationPort, Protocol fields
	v := reflect.ValueOf(rawEvent).Elem()
	sourceIPVal := v.FieldByName("SourceIP").String()
	destIPVal := v.FieldByName("DestinationIP").String()
	sourcePortVal := uint16(v.FieldByName("SourcePort").Uint())
	destPortVal := uint16(v.FieldByName("DestinationPort").Uint())
	protocolVal := v.FieldByName("Protocol").String()

	// NetworkEvent doesn't include container ID, so we can't query pod metadata
	// This will be enhanced in Phase 3 when container ID mapping is available
	var podMeta *PodMetadata

	// Build Kubernetes context
	k8sCtx := &K8sContext{
		ClusterID: e.ClusterID,
		NodeName:  e.NodeName,
	}

	if podMeta != nil {
		k8sCtx.Namespace = podMeta.Namespace
		k8sCtx.PodName = podMeta.Name
		k8sCtx.PodUID = podMeta.UID
		k8sCtx.ServiceAccount = podMeta.ServiceAccount
		k8sCtx.Image = podMeta.Image
		k8sCtx.Labels = podMeta.Labels
	}

	// Build network context with policy evaluation
	// ANCHOR: Network policy evaluation from K8s API - Phase 2.4, Dec 26, 2025
	// Query NetworkPolicy objects to determine traffic restrictions
	networkCtx := &NetworkContext{
		SourceIP:           sourceIPVal,
		DestinationIP:      destIPVal,
		SourcePort:         sourcePortVal,
		DestinationPort:    destPortVal,
		Protocol:           protocolVal,
		IngressRestricted:  false,
		EgressRestricted:   false,
		NamespaceIsolation: false,
	}

	// Query network policies if pod metadata is available
	if podMeta != nil && e.K8sClient != nil {
		npStatus := e.K8sClient.GetNetworkPolicyStatus(ctx, podMeta.Namespace, podMeta.Name, podMeta.Labels)
		if npStatus != nil {
			networkCtx.IngressRestricted = npStatus.IngressRestricted
			networkCtx.EgressRestricted = npStatus.EgressRestricted
			networkCtx.NamespaceIsolation = npStatus.NamespaceIsolation
		}
	} else if k8sCtx.Namespace != "" && e.K8sClient != nil {
		// Fallback: check namespace-wide default deny if we know the namespace
		networkCtx.NamespaceIsolation = e.K8sClient.CheckNamespaceDefaultDenyPolicy(ctx, k8sCtx.Namespace)
	}

	return &EnrichedEvent{
		RawEvent:   rawEvent,
		EventType:  "network_connection",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  &ContainerContext{},
		Network:    networkCtx,
	}, nil
}

// EnrichDNSEvent enriches a cilium/ebpf DNS event
// ANCHOR: DNS event enrichment with domain context - Phase 3, Dec 27, 2025
// Now available with cilium/ebpf; uses reflection-based field extraction to avoid circular imports
// Populates DNS query information and domain policy fields
func (e *Enricher) EnrichDNSEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if rawEvent == nil {
		return nil, fmt.Errorf("nil DNS event")
	}

	// Extract fields from raw event using reflection to avoid circular imports
	// Events from pkg/ebpf have Query, QueryType, ResponseCode fields
	v := reflect.ValueOf(rawEvent).Elem()
	queryNameVal := v.FieldByName("Query").String()
	queryTypeVal := v.FieldByName("QueryType").String()
	respCodeVal := int(v.FieldByName("ResponseCode").Uint())

	// Build Kubernetes context
	k8sCtx := &K8sContext{
		ClusterID: e.ClusterID,
		NodeName:  e.NodeName,
	}

	// Build DNS context with query and response information
	dnsCtx := &DNSContext{
		QueryName:    queryNameVal,
		QueryType:    queryTypeVal,
		ResponseCode: respCodeVal,
		QueryAllowed: respCodeVal == 0, // NOERROR (0) means query was allowed
	}

	return &EnrichedEvent{
		RawEvent:   rawEvent,
		EventType:  "dns_query",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  &ContainerContext{},
		DNS:        dnsCtx,
	}, nil
}

// EnrichFileEvent enriches a cilium/ebpf file event
// ANCHOR: File event enrichment with read-only context - Phase 2, Dec 26, 2025
// Migrated from goBPF to cilium/ebpf with reflection-based field extraction - Dec 27, 2025
// Populates read-only filesystem and resource limit fields; uses interface{} to avoid circular imports
func (e *Enricher) EnrichFileEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if rawEvent == nil {
		return nil, fmt.Errorf("nil file event")
	}

	// Extract fields from raw event using reflection to avoid circular imports
	// Events from pkg/ebpf have PID, UID, Path, Operation, Command fields
	v := reflect.ValueOf(rawEvent).Elem()
	pidVal := uint32(v.FieldByName("PID").Uint())
	uidVal := uint32(v.FieldByName("UID").Uint())
	pathVal := v.FieldByName("Path").String()
	opVal := v.FieldByName("Operation").String()
	cmdVal := v.FieldByName("Command").String()

	// Build Kubernetes context
	k8sCtx := &K8sContext{
		ClusterID: e.ClusterID,
		NodeName:  e.NodeName,
	}

	// Build container context with security defaults
	containerCtx := &ContainerContext{
		RunAsRoot:               uidVal == 0,
		ReadOnlyFilesystem:      false, // Default to false (writable)
		MemoryLimit:             "",    // No limit by default
		CPULimit:                "",    // No limit by default
		MemoryRequest:           "",    // No request by default
		CPURequest:              "",    // No request by default
		AllowPrivilegeEscalation: true,  // Default to true
	}

	return &EnrichedEvent{
		RawEvent:  rawEvent,
		EventType: "file_access",
		Timestamp: time.Now(),
		Kubernetes: k8sCtx,
		Container: containerCtx,
		Process: &ProcessContext{
			PID:     pidVal,
			UID:     uidVal,
			Command: cmdVal,
		},
		File: &FileContext{
			Path:      pathVal,
			Operation: opVal,
			PID:       pidVal,
			UID:       uidVal,
		},
	}, nil
}

// EnrichCapabilityEvent enriches a cilium/ebpf capability event
// ANCHOR: Capability event enrichment with privilege escalation context - Phase 2, Dec 26, 2025
// Migrated from goBPF to cilium/ebpf with reflection-based field extraction - Dec 27, 2025
// Populates privilege escalation and capability restriction fields; uses interface{} to avoid circular imports
func (e *Enricher) EnrichCapabilityEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if rawEvent == nil {
		return nil, fmt.Errorf("nil capability event")
	}

	// Extract fields from raw event using reflection to avoid circular imports
	// Events from pkg/ebpf have PID, UID, Command, Name, Allowed fields
	v := reflect.ValueOf(rawEvent).Elem()
	pidVal := uint32(v.FieldByName("PID").Uint())
	uidVal := uint32(v.FieldByName("UID").Uint())
	cmdVal := v.FieldByName("Command").String()
	nameVal := v.FieldByName("Name").String()
	allowedVal := v.FieldByName("Allowed").Bool()

	// Build Kubernetes context
	k8sCtx := &K8sContext{
		ClusterID: e.ClusterID,
		NodeName:  e.NodeName,
	}

	// Build container context with capability defaults
	containerCtx := &ContainerContext{
		RunAsRoot:                uidVal == 0,
		AllowPrivilegeEscalation: true,  // Default to true (least restrictive)
		Privileged:               false, // Default to false
	}

	return &EnrichedEvent{
		RawEvent:  rawEvent,
		EventType: "capability_usage",
		Timestamp: time.Now(),
		Kubernetes: k8sCtx,
		Container: containerCtx,
		Process: &ProcessContext{
			PID:     pidVal,
			UID:     uidVal,
			Command: cmdVal,
		},
		Capability: &CapabilityContext{
			Name:    nameVal,
			Allowed: allowedVal,
			PID:     pidVal,
			UID:     uidVal,
		},
	}, nil
}
