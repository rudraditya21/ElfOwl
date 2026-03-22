// ANCHOR: Event enrichment pipeline - Dec 26, 2025
// Converts cilium/ebpf events to enriched events with K8s and container context
// Phase 3: Migrated from goBPF to cilium/ebpf (Dec 27, 2025)

package enrichment

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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

// ANCHOR: Reflection helpers for eBPF events - Phase 3 debugging support - Jan 2026
var dnsQueryTypeNames = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	42:  "NAPTR",
	43:  "DS",
	48:  "DNSKEY",
	255: "ANY",
}

var dnsResponseCodeNames = map[uint8]string{
	0:  "NOERROR",
	1:  "FORMERR",
	2:  "SERVFAIL",
	3:  "NXDOMAIN",
	4:  "NOTIMP",
	5:  "REFUSED",
	6:  "YXDOMAIN",
	7:  "YXRRSET",
	8:  "NXRRSET",
	9:  "NOTAUTH",
	10: "NOTZONE",
}

var capabilityNames = map[uint32]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETFCAP",
	9:  "CAP_SETPCAP",
	10: "CAP_NET_RAW",
	11: "CAP_NET_BIND_SERVICE",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_BROADCAST",
	14: "CAP_SYS_CHROOT",
	15: "CAP_SYS_MODULE",
	16: "CAP_SYS_PTRACE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_PACCT",
	19: "CAP_SYS_ADMIN",
	20: "CAP_SYS_BOOT",
	21: "CAP_SYS_NICE",
	22: "CAP_SYS_RESOURCE",
	23: "CAP_SYS_TIME",
	24: "CAP_SYS_TTY_CONFIG",
	25: "CAP_MKNOD",
	26: "CAP_LEASE",
	27: "CAP_AUDIT_WRITE",
	28: "CAP_AUDIT_CONTROL",
	29: "CAP_SETFATTR",
	30: "CAP_MAC_OVERRIDE",
	31: "CAP_MAC_ADMIN",
	32: "CAP_SYSLOG",
	33: "CAP_WAKE_ALARM",
	34: "CAP_BLOCK_SUSPEND",
	35: "CAP_AUDIT_READ",
	36: "CAP_PERFMON",
	37: "CAP_BPF",
	38: "CAP_CHECKPOINT_RESTORE",
}

func resolveEventValue(raw interface{}) (reflect.Value, error) {
	v := reflect.ValueOf(raw)
	if !v.IsValid() {
		return reflect.Value{}, fmt.Errorf("invalid event")
	}
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return reflect.Value{}, fmt.Errorf("nil event pointer")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("expected struct event, got %s", v.Kind())
	}
	return v, nil
}

func fieldUintValue(v reflect.Value, name string) uint64 {
	f := v.FieldByName(name)
	if !f.IsValid() {
		return 0
	}
	switch f.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
		return f.Uint()
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int:
		return uint64(f.Int())
	default:
		return 0
	}
}

func fieldStringValue(v reflect.Value, name string) string {
	f := v.FieldByName(name)
	if !f.IsValid() {
		return ""
	}
	switch f.Kind() {
	case reflect.Array, reflect.Slice:
		b := make([]byte, f.Len())
		for i := 0; i < f.Len(); i++ {
			elem := f.Index(i)
			if elem.Kind() == reflect.Uint8 {
				b[i] = byte(elem.Uint())
			}
		}
		return strings.TrimRight(string(b), "\x00")
	case reflect.String:
		return f.String()
	default:
		return ""
	}
}

func ipFromUint32(addr uint32) string {
	return net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24)).String()
}

func protocolName(proto uint64) string {
	switch proto {
	case 17:
		return "udp"
	case 6:
		return "tcp"
	default:
		return "unknown"
	}
}

func fileOperationName(op uint64) string {
	switch op {
	case 1:
		return "write"
	case 2:
		return "read"
	case 3:
		return "chmod"
	case 4:
		return "unlink"
	default:
		return "unknown"
	}
}

func dnsQueryTypeName(qtype uint16) string {
	if name, ok := dnsQueryTypeNames[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

func dnsResponseCodeName(rcode uint8) string {
	if name, ok := dnsResponseCodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

func capabilityNameFromID(id uint32) string {
	if name, ok := capabilityNames[id]; ok {
		return name
	}
	return fmt.Sprintf("CAP_UNKNOWN_%d", id)
}

// ANCHOR: Proc-based enrichment fallback - Feature: parent/args/container - Jan 2026
// Uses /proc to recover process args, parent PID, and container ID when eBPF events omit them.
func procCmdline(pid uint32) []string {
	if pid == 0 {
		return nil
	}
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "cmdline"))
	if err != nil || len(data) == 0 {
		return nil
	}
	parts := strings.Split(string(data), "\x00")
	args := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		args = append(args, part)
	}
	return args
}

func procParentPID(pid uint32) uint32 {
	if pid == 0 {
		return 0
	}
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "stat"))
	if err != nil {
		return 0
	}
	// /proc/<pid>/stat: pid (comm) state ppid ...
	// We need the field after the closing ')'.
	stat := string(data)
	closeIdx := strings.LastIndex(stat, ")")
	if closeIdx == -1 || closeIdx+2 >= len(stat) {
		return 0
	}
	fields := strings.Fields(stat[closeIdx+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(ppid)
}

func procContainerID(pid uint32) string {
	if pid == 0 {
		return ""
	}
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup"))
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		segments := strings.Split(path, "/")
		for i := len(segments) - 1; i >= 0; i-- {
			seg := segments[i]
			if seg == "" {
				continue
			}
			// ANCHOR: Robust container ID parsing - Bugfix: containerd/cri-o cgroup paths - Mar 22, 2026
			// Normalize common runtime prefixes/suffixes and require hex IDs to avoid
			// mistaking pod UID segments for container IDs.
			seg = strings.TrimSuffix(seg, ".scope")
			seg = strings.TrimPrefix(seg, "docker-")
			seg = strings.TrimPrefix(seg, "containerd-")
			seg = strings.TrimPrefix(seg, "cri-containerd-")
			seg = strings.TrimPrefix(seg, "crio-")
			seg = strings.TrimPrefix(seg, "cri-o-")
			seg = strings.TrimPrefix(seg, "libpod-")

			// Container IDs are typically 64-hex chars; accept 32+ as fallback.
			seg = strings.ToLower(seg)
			if len(seg) >= 32 && isHexString(seg) {
				return seg
			}
		}
	}
	return ""
}

func isHexString(value string) bool {
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
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

	// Extract fields from raw event using reflection (no pkg/ebpf import)
	v, err := resolveEventValue(rawEvent)
	if err != nil {
		return nil, err
	}
	pidVal := uint32(fieldUintValue(v, "PID"))
	uidVal := uint32(fieldUintValue(v, "UID"))
	gidVal := uint32(fieldUintValue(v, "GID"))
	cmdVal := fieldStringValue(v, "Argv")
	if cmdVal == "" {
		cmdVal = fieldStringValue(v, "Filename")
	}
	fnVal := fieldStringValue(v, "Filename")
	argsVal := strings.Fields(cmdVal)
	if len(argsVal) == 0 {
		argsVal = procCmdline(pidVal)
	}
	parentPID := procParentPID(pidVal)
	containerID := procContainerID(pidVal)

	containerCtx := &ContainerContext{
		ContainerID: containerID,
		RunAsRoot:   false, // Will be set below based on podMeta or eBPF UID
	}

	// Get pod metadata from K8s API (returns nil if not available)
	podMeta := e.getPodMetadata(ctx, containerID)

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
		containerCtx.ContainerName = podMeta.ContainerName

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
		containerCtx.AllowPrivilegeEscalation = true // Default to true (least restrictive)
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
		RawEvent:   rawEvent,
		EventType:  "process_execution",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  containerCtx,
		Process: &ProcessContext{
			PID:         uint32(pidVal),
			ParentPID:   parentPID,
			UID:         uint32(uidVal),
			GID:         uint32(gidVal),
			Command:     cmdVal,
			Arguments:   argsVal,
			Filename:    fnVal,
			ContainerID: containerID,
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

	v, err := resolveEventValue(rawEvent)
	if err != nil {
		return nil, err
	}
	sourceIPVal := ipFromUint32(uint32(fieldUintValue(v, "SAddr")))
	destIPVal := ipFromUint32(uint32(fieldUintValue(v, "DAddr")))
	sourcePortVal := uint16(fieldUintValue(v, "SPort"))
	destPortVal := uint16(fieldUintValue(v, "DPort"))
	protocolVal := protocolName(fieldUintValue(v, "Protocol"))

	// ANCHOR: Container context propagation - Feature: PID-based container lookup - Jan 2026
	// Resolve container metadata from PID when available
	pidVal := uint32(fieldUintValue(v, "PID"))
	containerID := procContainerID(pidVal)
	containerCtx := &ContainerContext{
		ContainerID: containerID,
	}
	podMeta := e.getPodMetadata(ctx, containerID)

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
		containerCtx.ContainerName = podMeta.ContainerName
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
			// ANCHOR: Default deny policy flag on network events - Bugfix: CIS_4.6.1 false positives - Mar 22, 2026
			// Populate Kubernetes.HasDefaultDenyNetworkPolicy so CIS_4.6.1 evaluates correctly.
			k8sCtx.HasDefaultDenyNetworkPolicy = npStatus.NamespaceIsolation
		}
	} else if k8sCtx.Namespace != "" && e.K8sClient != nil {
		// Fallback: check namespace-wide default deny if we know the namespace
		networkCtx.NamespaceIsolation = e.K8sClient.CheckNamespaceDefaultDenyPolicy(ctx, k8sCtx.Namespace)
		k8sCtx.HasDefaultDenyNetworkPolicy = networkCtx.NamespaceIsolation
	}

	return &EnrichedEvent{
		RawEvent:   rawEvent,
		EventType:  "network_connection",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  containerCtx,
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

	v, err := resolveEventValue(rawEvent)
	if err != nil {
		return nil, err
	}
	queryNameVal := fieldStringValue(v, "QueryName")
	queryTypeVal := dnsQueryTypeName(uint16(fieldUintValue(v, "QueryType")))
	respCodeVal := int(fieldUintValue(v, "ResponseCode"))
	queryAllowed := fieldUintValue(v, "QueryAllowed") == 1

	// ANCHOR: Container context propagation - Feature: PID-based container lookup - Jan 2026
	// Resolve container metadata from PID when available
	pidVal := uint32(fieldUintValue(v, "PID"))
	containerID := procContainerID(pidVal)
	containerCtx := &ContainerContext{
		ContainerID: containerID,
	}
	podMeta := e.getPodMetadata(ctx, containerID)

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
		containerCtx.ContainerName = podMeta.ContainerName
	}

	// Build DNS context with query and response information
	dnsCtx := &DNSContext{
		QueryName:    queryNameVal,
		QueryType:    queryTypeVal,
		ResponseCode: respCodeVal,
		QueryAllowed: queryAllowed,
	}

	return &EnrichedEvent{
		RawEvent:   rawEvent,
		EventType:  "dns_query",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  containerCtx,
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

	v, err := resolveEventValue(rawEvent)
	if err != nil {
		return nil, err
	}
	pidVal := uint32(fieldUintValue(v, "PID"))
	uidVal := uint32(fieldUintValue(v, "UID"))
	pathVal := fieldStringValue(v, "Filename")
	opVal := fileOperationName(fieldUintValue(v, "Operation"))
	cmdVal := fieldStringValue(v, "Filename")

	// ANCHOR: Container context propagation - Feature: PID-based container lookup - Jan 2026
	// Resolve container metadata from PID when available
	containerID := procContainerID(pidVal)
	containerCtx := &ContainerContext{
		ContainerID: containerID,
	}
	podMeta := e.getPodMetadata(ctx, containerID)

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
		containerCtx.ContainerName = podMeta.ContainerName
	}

	// Build container context with security defaults
	containerCtx.RunAsRoot = uidVal == 0
	containerCtx.ReadOnlyFilesystem = false // Default to false (writable)
	containerCtx.MemoryLimit = ""           // No limit by default
	containerCtx.CPULimit = ""              // No limit by default
	containerCtx.MemoryRequest = ""         // No request by default
	containerCtx.CPURequest = ""            // No request by default
	containerCtx.AllowPrivilegeEscalation = true

	return &EnrichedEvent{
		RawEvent:   rawEvent,
		EventType:  "file_access",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  containerCtx,
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

	v, err := resolveEventValue(rawEvent)
	if err != nil {
		return nil, err
	}
	pidVal := uint32(fieldUintValue(v, "PID"))
	uidVal := uint32(fieldUintValue(v, "UID"))
	cmdVal := fieldStringValue(v, "SyscallName")
	if cmdVal == "" {
		cmdVal = fieldStringValue(v, "Command")
	}
	capabilityID := uint32(fieldUintValue(v, "Capability"))
	allowedVal := fieldUintValue(v, "CheckType") != 2
	nameVal := capabilityNameFromID(capabilityID)

	// ANCHOR: Container context propagation - Feature: PID-based container lookup - Jan 2026
	// Resolve container metadata from PID when available
	containerID := procContainerID(pidVal)
	containerCtx := &ContainerContext{
		ContainerID: containerID,
	}
	podMeta := e.getPodMetadata(ctx, containerID)

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
		containerCtx.ContainerName = podMeta.ContainerName
	}

	// Build container context with capability defaults
	containerCtx.RunAsRoot = uidVal == 0
	containerCtx.AllowPrivilegeEscalation = true // Default to true (least restrictive)
	containerCtx.Privileged = false              // Default to false

	return &EnrichedEvent{
		RawEvent:   rawEvent,
		EventType:  "capability_usage",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  containerCtx,
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
