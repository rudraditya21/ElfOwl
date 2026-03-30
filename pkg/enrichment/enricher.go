// ANCHOR: Event enrichment pipeline - Dec 26, 2025
// Converts cilium/ebpf events to enriched events with K8s and container context
// Phase 3: Migrated from goBPF to cilium/ebpf (Dec 27, 2025)

package enrichment

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

	// ANCHOR: cgroupID to containerID cache - Fix PR-23 #3 /proc race - Mar 25, 2026
	// CgroupID is captured in kernel at event time (race-free). Used as fallback when
	// /proc/<pid>/cgroup is unreadable (process already exited).
	cgroupToContainerMutex sync.RWMutex
	cgroupToContainerCache map[uint64]string // cgroupID -> containerID

	// ANCHOR: cgroup refresh guard - Fix PR-23 #3 residual first-event drop - Mar 25, 2026
	// Throttles expensive cgroup<->pod refresh scans on repeated cold-cache misses.
	cgroupRefreshMutex sync.Mutex
	lastCgroupRefresh  time.Time
}

const cgroupMappingRefreshInterval = 30 * time.Second
const enrichmentK8sTimeout = 2 * time.Second

func withEnrichmentTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	if timeout <= 0 {
		return ctx, func() {}
	}

	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) <= timeout {
			return ctx, func() {}
		}
	}

	return context.WithTimeout(ctx, timeout)
}

// NewEnricher creates a new event enricher
// ANCHOR: Enricher initialization without circular dependency - Dec 26, 2025
// Pass only needed fields (ClusterID, NodeName) instead of full Config to avoid import cycle
func NewEnricher(k8sClient *kubernetes.Client, clusterID, nodeName string) (*Enricher, error) {
	logger, _ := zap.NewProduction()

	enricher := &Enricher{
		K8sClient:              k8sClient,
		ClusterID:              clusterID,
		NodeName:               nodeName,
		Logger:                 logger,
		cgroupToContainerCache: make(map[uint64]string),
	}

	// Warm up cgroup mappings once on startup to reduce first-event drops when /proc races.
	if enricher.K8sClient != nil {
		warmCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		enricher.refreshCgroupPodMappings(warmCtx, true)
	}

	return enricher, nil
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

func networkDirectionName(direction uint64) string {
	switch direction {
	case 1:
		return "outbound"
	case 2:
		return "inbound"
	default:
		return "unknown"
	}
}

func tcpConnectionStateName(state uint64) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	case 12:
		return "NEW_SYN_RECV"
	default:
		return "UNKNOWN"
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

func normalizeContainerIDSegment(seg string) string {
	if seg == "" {
		return ""
	}
	seg = strings.TrimSuffix(seg, ".scope")
	seg = strings.TrimPrefix(seg, "docker-")
	seg = strings.TrimPrefix(seg, "containerd-")
	seg = strings.TrimPrefix(seg, "cri-containerd-")
	seg = strings.TrimPrefix(seg, "crio-")
	seg = strings.TrimPrefix(seg, "cri-o-")
	seg = strings.TrimPrefix(seg, "libpod-")

	seg = strings.ToLower(seg)
	if len(seg) >= 32 && isHexString(seg) {
		return seg
	}
	return ""
}

func containerIDFromPath(path string) string {
	segments := strings.Split(path, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		if id := normalizeContainerIDSegment(segments[i]); id != "" {
			return id
		}
	}
	return ""
}

func normalizeContainerIDValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		parts := strings.SplitN(value, "://", 2)
		value = parts[1]
	}
	if strings.Contains(value, "/") {
		if id := containerIDFromPath(value); id != "" {
			return id
		}
	}
	return normalizeContainerIDSegment(value)
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
		if id := containerIDFromPath(parts[2]); id != "" {
			return id
		}
	}
	return ""
}

var errCgroupInodeMatch = errors.New("cgroup inode match")

func containerIDFromCgroupID(cgroupID uint64) string {
	if cgroupID == 0 {
		return ""
	}

	var resolved string
	walkErr := filepath.WalkDir("/sys/fs/cgroup", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || !d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat == nil || stat.Ino != cgroupID {
			return nil
		}

		if id := containerIDFromPath(path); id != "" {
			resolved = id
			return errCgroupInodeMatch
		}
		return nil
	})

	if walkErr != nil && !errors.Is(walkErr, errCgroupInodeMatch) {
		return ""
	}
	return resolved
}

func scanCgroupContainerMappings() map[string]uint64 {
	mappings := make(map[string]uint64)

	_ = filepath.WalkDir("/sys/fs/cgroup", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || !d.IsDir() {
			return nil
		}
		containerID := containerIDFromPath(path)
		if containerID == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat == nil || stat.Ino == 0 {
			return nil
		}
		mappings[containerID] = stat.Ino
		return nil
	})

	return mappings
}

func (e *Enricher) resolvePodMetadataFromCgroupMapping(ctx context.Context, cgroupID uint64) (*PodMetadata, error) {
	if e.K8sClient == nil || cgroupID == 0 {
		return nil, nil
	}
	mapping, found := e.K8sClient.GetCache().GetCgroupMapping(cgroupID)
	if !found || mapping == "" {
		return nil, nil
	}
	parts := strings.SplitN(mapping, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, nil
	}
	containerName := ""
	if len(parts) == 3 {
		containerName = parts[2]
	}
	metadata, err := e.K8sClient.GetPodMetadataForContainer(ctx, parts[0], parts[1], containerName)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

func (e *Enricher) refreshCgroupPodMappings(ctx context.Context, force bool) {
	if e.K8sClient == nil {
		return
	}

	e.cgroupRefreshMutex.Lock()
	defer e.cgroupRefreshMutex.Unlock()

	if !force && !e.lastCgroupRefresh.IsZero() && time.Since(e.lastCgroupRefresh) < cgroupMappingRefreshInterval {
		return
	}
	e.lastCgroupRefresh = time.Now()

	containerCgroupMap := scanCgroupContainerMappings()
	if len(containerCgroupMap) == 0 {
		return
	}

	pods, err := e.K8sClient.ListAllPods(ctx)
	if err != nil {
		e.Logger.Debug("failed to refresh cgroup mappings from pod list", zap.Error(err))
		return
	}

	for baseMapping, podMeta := range pods {
		if podMeta == nil {
			continue
		}

		// ANCHOR: Multi-container cgroup mapping registration - Fix PR-23 #6 - Mar 26, 2026
		// Loop over all container IDs (main + init + ephemeral) so every container in a pod
		// gets a cgroupID → pod mapping registered. Previously only the first container was mapped.
		containerIDs := podMeta.ContainerIDs
		if len(containerIDs) == 0 && podMeta.ContainerID != "" {
			containerIDs = []string{podMeta.ContainerID}
		}
		for _, rawID := range containerIDs {
			containerID := normalizeContainerIDValue(rawID)
			if containerID == "" {
				continue
			}
			cgroupID, found := containerCgroupMap[containerID]
			if !found || cgroupID == 0 {
				continue
			}

			e.cgroupToContainerMutex.Lock()
			e.cgroupToContainerCache[cgroupID] = containerID
			e.cgroupToContainerMutex.Unlock()

			mapping := baseMapping
			if podMeta.ContainerIDToName != nil {
				if containerName, ok := podMeta.ContainerIDToName[containerID]; ok && containerName != "" {
					mapping = fmt.Sprintf("%s/%s/%s", podMeta.Namespace, podMeta.Name, containerName)
				}
			}

			e.K8sClient.GetCache().SetContainerMapping(containerID, mapping)
			e.K8sClient.GetCache().SetCgroupMapping(cgroupID, mapping)
		}
	}
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
// cgroupID uint64 is used as fallback when /proc lookup fails (short-lived process race).
func (e *Enricher) getPodMetadata(ctx context.Context, containerID string, cgroupID uint64) (*PodMetadata, error) {
	if e.K8sClient == nil {
		return nil, nil
	}

	// ANCHOR: CgroupID fallback lookup - Fix PR-23 #3 /proc race - Mar 25, 2026
	// If /proc lookup failed (process exited), try multiple fallback paths:
	// 1. Local cgroupID -> containerID cache
	// 2. Resolve container ID directly from cgroup inode under /sys/fs/cgroup
	// 3. K8s client cgroupID -> pod mapping cache (if available)
	// 4. On miss, refresh cgroup<->pod mappings from /sys/fs/cgroup + K8s pods and retry
	if containerID == "" && cgroupID != 0 {
		// First try enricher's local cgroup->container cache
		e.cgroupToContainerMutex.RLock()
		cached, found := e.cgroupToContainerCache[cgroupID]
		e.cgroupToContainerMutex.RUnlock()
		if found && cached != "" {
			containerID = cached
		} else if resolved := containerIDFromCgroupID(cgroupID); resolved != "" {
			containerID = resolved
			e.cgroupToContainerMutex.Lock()
			e.cgroupToContainerCache[cgroupID] = containerID
			e.cgroupToContainerMutex.Unlock()
		}

		if containerID == "" {
			// Try K8s client's cgroup->pod mapping for direct resolution
			metadata, err := e.resolvePodMetadataFromCgroupMapping(ctx, cgroupID)
			if err != nil {
				e.Logger.Debug("failed to resolve pod by cgroup mapping", zap.Uint64("cgroupID", cgroupID), zap.Error(err))
				return nil, err
			}
			if metadata != nil {
				return metadata, nil
			}

			// Cold-cache fallback for first event: refresh cgroup<->pod mapping and retry once.
			e.refreshCgroupPodMappings(ctx, false)
			metadata, err = e.resolvePodMetadataFromCgroupMapping(ctx, cgroupID)
			if err != nil {
				e.Logger.Debug("failed to resolve pod by refreshed cgroup mapping", zap.Uint64("cgroupID", cgroupID), zap.Error(err))
				return nil, err
			}
			if metadata != nil {
				return metadata, nil
			}
		}
	}

	if containerID == "" {
		return nil, nil
	}

	// Use Kubernetes client cache as the single source of truth for container mappings.
	cachedMapping, found := e.K8sClient.GetCache().GetContainerMapping(containerID)

	if found {
		// Parse cached mapping: "namespace/podname[/container]"
		parts := strings.SplitN(cachedMapping, "/", 3)
		if len(parts) >= 2 {
			namespace := parts[0]
			podName := parts[1]
			containerName := ""
			if len(parts) == 3 {
				containerName = parts[2]
			}

			if containerName == "" {
				// Backward-compatible path for old cache entries that only stored namespace/pod.
				// Resolve again via container ID to recover the specific container context.
				metadata, err := e.K8sClient.GetPodByContainerID(ctx, containerID)
				if err == nil && metadata != nil {
					mapping := fmt.Sprintf("%s/%s", metadata.Namespace, metadata.Name)
					if metadata.ContainerName != "" {
						mapping = fmt.Sprintf("%s/%s/%s", metadata.Namespace, metadata.Name, metadata.ContainerName)
					}
					e.K8sClient.GetCache().SetContainerMapping(containerID, mapping)
					return metadata, nil
				}
			}

			// Use K8s client to retrieve pod metadata with container-specific context.
			metadata, err := e.K8sClient.GetPodMetadataForContainer(ctx, namespace, podName, containerName)
			if err != nil {
				e.Logger.Debug("failed to get pod metadata from cache", zap.Error(err))
				return nil, err
			}
			return metadata, nil
		}
	}

	// Query K8s API for pod lookup by container ID
	metadata, err := e.K8sClient.GetPodByContainerID(ctx, containerID)
	if err != nil {
		e.Logger.Debug("failed to find pod by container ID", zap.String("containerID", containerID), zap.Error(err))
		return nil, err
	}

	if metadata != nil {
		// Cache the mapping locally for future use
		mapping := fmt.Sprintf("%s/%s", metadata.Namespace, metadata.Name)
		if metadata.ContainerName != "" {
			mapping = fmt.Sprintf("%s/%s/%s", metadata.Namespace, metadata.Name, metadata.ContainerName)
		}
		e.K8sClient.GetCache().SetContainerMapping(containerID, mapping)

		// Also cache cgroupID -> containerID mapping for fast fallback lookups
		if cgroupID != 0 {
			e.cgroupToContainerMutex.Lock()
			e.cgroupToContainerCache[cgroupID] = containerID
			e.cgroupToContainerMutex.Unlock()

			// Register cgroup->pod mapping in K8s client cache for first-time events
			e.K8sClient.GetCache().SetCgroupMapping(cgroupID, mapping)
		}
	}

	return metadata, nil
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

// ANCHOR: Compliance field propagation - Feature: image/volume/kernel signals - Mar 22, 2026
// Applies pod-derived compliance fields to container context for CIS rule evaluation.
func applyPodComplianceFields(containerCtx *ContainerContext, podMeta *PodMetadata) {
	if containerCtx == nil || podMeta == nil {
		return
	}
	containerCtx.ImageScanStatus = podMeta.ImageScanStatus
	containerCtx.ImageRegistryAuth = podMeta.ImageRegistryAuth
	containerCtx.ImageSigned = podMeta.ImageSigned
	containerCtx.StorageRequest = podMeta.StorageRequest
	containerCtx.VolumeType = podMeta.VolumeType
	containerCtx.Runtime = podMeta.Runtime
	containerCtx.IsolationLevel = podMeta.IsolationLevel
	containerCtx.KernelHardening = podMeta.KernelHardening
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
	if e.K8sClient != nil {
		var cancel context.CancelFunc
		ctx, cancel = withEnrichmentTimeout(ctx, enrichmentK8sTimeout)
		defer cancel()
	}

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
	cgroupIDVal := fieldUintValue(v, "CgroupID")
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
	podMeta, err := e.getPodMetadata(ctx, containerID, cgroupIDVal)
	if err != nil {
		return nil, err
	}

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
		if podMeta.OwnerRef != nil {
			k8sCtx.OwnerRef = &OwnerReference{
				Kind: podMeta.OwnerRef.Kind,
				Name: podMeta.OwnerRef.Name,
				UID:  podMeta.OwnerRef.UID,
			}
		}
		k8sCtx.AuditLoggingEnabled = podMeta.AuditLoggingEnabled
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
				} else if podMeta.ServiceAccountTokenTTLSeconds > 0 {
					// Projected SA tokens (K8s 1.22+) are not persisted as Secrets.
					// Use configured token lifetime as an age/lifetime surrogate signal.
					k8sCtx.ServiceAccountTokenAge = podMeta.ServiceAccountTokenTTLSeconds
				}
			}

			// Get RBAC privilege level (0=restricted, 1=standard, 2=elevated, 3=admin)
			k8sCtx.RBACLevel = e.K8sClient.GetRBACLevel(ctx, podMeta.Namespace, podMeta.ServiceAccount)
			k8sCtx.RBACEnforced = e.K8sClient.IsRBACAPIEnabled(ctx)

			// Count permission grants
			k8sCtx.ServiceAccountPermissions = e.K8sClient.CountRBACPermissions(ctx, podMeta.Namespace, podMeta.ServiceAccount)
			k8sCtx.RolePermissionCount = e.K8sClient.MaxRolePermissionCount(ctx, podMeta.Namespace, podMeta.ServiceAccount)
			k8sCtx.RBACPolicyDefined = e.K8sClient.HasRBACPolicy(ctx, podMeta.Namespace, podMeta.ServiceAccount)
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
		// ANCHOR: Compliance fields from pod metadata - Feature: image/volume/kernel signals - Mar 22, 2026
		// Propagates pod-derived compliance signals into process events for CIS checks.
		applyPodComplianceFields(containerCtx, podMeta)
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

	enriched := &EnrichedEvent{
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
	}

	// ANCHOR: K8s-native filter - Requirement: discard host events - Mar 24, 2026
	// Return sentinel so the agent can decide (per kubernetes_only config) whether to discard.
	if k8sCtx.PodUID == "" {
		return enriched, ErrNoKubernetesContext
	}

	return enriched, nil
}

// EnrichNetworkEvent enriches a cilium/ebpf network event
// ANCHOR: Network event enrichment with policy context - Phase 2, Dec 26, 2025
// Migrated from goBPF to cilium/ebpf with reflection-based field extraction - Dec 27, 2025
// Populates network policy and namespace isolation fields; uses interface{} to avoid circular imports
func (e *Enricher) EnrichNetworkEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if e.K8sClient != nil {
		var cancel context.CancelFunc
		ctx, cancel = withEnrichmentTimeout(ctx, enrichmentK8sTimeout)
		defer cancel()
	}

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
	cgroupIDVal := fieldUintValue(v, "CgroupID")
	containerID := procContainerID(pidVal)
	containerCtx := &ContainerContext{
		ContainerID: containerID,
	}
	podMeta, err := e.getPodMetadata(ctx, containerID, cgroupIDVal)
	if err != nil {
		return nil, err
	}

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
		if podMeta.OwnerRef != nil {
			k8sCtx.OwnerRef = &OwnerReference{
				Kind: podMeta.OwnerRef.Kind,
				Name: podMeta.OwnerRef.Name,
				UID:  podMeta.OwnerRef.UID,
			}
		}
		k8sCtx.AuditLoggingEnabled = podMeta.AuditLoggingEnabled
		containerCtx.ContainerName = podMeta.ContainerName
		// ANCHOR: Compliance fields for network events - Feature: image/volume/kernel signals - Mar 22, 2026
		// Propagates pod-derived compliance signals into network events for rule evaluation.
		applyPodComplianceFields(containerCtx, podMeta)
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
		Direction:          networkDirectionName(fieldUintValue(v, "Direction")),
		ConnectionState:    tcpConnectionStateName(fieldUintValue(v, "State")),
		NetworkNamespaceID: uint32(fieldUintValue(v, "NetNS")),
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

	enriched := &EnrichedEvent{
		RawEvent:   rawEvent,
		EventType:  "network_connection",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  containerCtx,
		Network:    networkCtx,
	}

	// ANCHOR: K8s-native filter - Requirement: discard host events - Mar 24, 2026
	// Return sentinel so the agent can decide (per kubernetes_only config) whether to discard.
	if k8sCtx.PodUID == "" {
		return enriched, ErrNoKubernetesContext
	}

	return enriched, nil
}

// EnrichDNSEvent enriches a cilium/ebpf DNS event
// ANCHOR: DNS event enrichment with domain context - Phase 3, Dec 27, 2025
// Now available with cilium/ebpf; uses reflection-based field extraction to avoid circular imports
// Populates DNS query information and domain policy fields
func (e *Enricher) EnrichDNSEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if e.K8sClient != nil {
		var cancel context.CancelFunc
		ctx, cancel = withEnrichmentTimeout(ctx, enrichmentK8sTimeout)
		defer cancel()
	}

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
	cgroupIDVal := fieldUintValue(v, "CgroupID")
	containerID := procContainerID(pidVal)
	containerCtx := &ContainerContext{
		ContainerID: containerID,
	}
	podMeta, err := e.getPodMetadata(ctx, containerID, cgroupIDVal)
	if err != nil {
		return nil, err
	}

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
		if podMeta.OwnerRef != nil {
			k8sCtx.OwnerRef = &OwnerReference{
				Kind: podMeta.OwnerRef.Kind,
				Name: podMeta.OwnerRef.Name,
				UID:  podMeta.OwnerRef.UID,
			}
		}
		k8sCtx.AuditLoggingEnabled = podMeta.AuditLoggingEnabled
		containerCtx.ContainerName = podMeta.ContainerName
		// ANCHOR: Compliance fields for DNS events - Feature: image/volume/kernel signals - Mar 22, 2026
		// Propagates pod-derived compliance signals into DNS events for rule evaluation.
		applyPodComplianceFields(containerCtx, podMeta)
	}

	// Build DNS context with query and response information
	dnsCtx := &DNSContext{
		QueryName:    queryNameVal,
		QueryType:    queryTypeVal,
		ResponseCode: respCodeVal,
		QueryAllowed: queryAllowed,
	}

	enriched := &EnrichedEvent{
		RawEvent:   rawEvent,
		EventType:  "dns_query",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  containerCtx,
		DNS:        dnsCtx,
	}

	// ANCHOR: K8s-native filter - Requirement: discard host events - Mar 24, 2026
	// Return sentinel so the agent can decide (per kubernetes_only config) whether to discard.
	if k8sCtx.PodUID == "" {
		return enriched, ErrNoKubernetesContext
	}

	return enriched, nil
}

// EnrichFileEvent enriches a cilium/ebpf file event
// ANCHOR: File event enrichment with read-only context - Phase 2, Dec 26, 2025
// Migrated from goBPF to cilium/ebpf with reflection-based field extraction - Dec 27, 2025
// Populates read-only filesystem and resource limit fields; uses interface{} to avoid circular imports
func (e *Enricher) EnrichFileEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if e.K8sClient != nil {
		var cancel context.CancelFunc
		ctx, cancel = withEnrichmentTimeout(ctx, enrichmentK8sTimeout)
		defer cancel()
	}

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
	cgroupIDVal := fieldUintValue(v, "CgroupID")

	// ANCHOR: Container context propagation - Feature: PID-based container lookup - Jan 2026
	// Resolve container metadata from PID when available
	containerID := procContainerID(pidVal)
	containerCtx := &ContainerContext{
		ContainerID: containerID,
	}
	podMeta, err := e.getPodMetadata(ctx, containerID, cgroupIDVal)
	if err != nil {
		return nil, err
	}

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
		if podMeta.OwnerRef != nil {
			k8sCtx.OwnerRef = &OwnerReference{
				Kind: podMeta.OwnerRef.Kind,
				Name: podMeta.OwnerRef.Name,
				UID:  podMeta.OwnerRef.UID,
			}
		}
		k8sCtx.AuditLoggingEnabled = podMeta.AuditLoggingEnabled
		containerCtx.ContainerName = podMeta.ContainerName
		// ANCHOR: Compliance fields for file events - Feature: image/volume/kernel signals - Mar 22, 2026
		// Propagates pod-derived compliance signals into file events for rule evaluation.
		applyPodComplianceFields(containerCtx, podMeta)
	}

	// Build container context with security defaults
	containerCtx.RunAsRoot = uidVal == 0
	containerCtx.ReadOnlyFilesystem = false // Default to false (writable)
	containerCtx.MemoryLimit = ""           // No limit by default
	containerCtx.CPULimit = ""              // No limit by default
	containerCtx.MemoryRequest = ""         // No request by default
	containerCtx.CPURequest = ""            // No request by default
	containerCtx.AllowPrivilegeEscalation = true

	enriched := &EnrichedEvent{
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
	}

	// ANCHOR: K8s-native filter - Requirement: discard host events - Mar 24, 2026
	// Return sentinel so the agent can decide (per kubernetes_only config) whether to discard.
	if k8sCtx.PodUID == "" {
		return enriched, ErrNoKubernetesContext
	}

	return enriched, nil
}

// EnrichCapabilityEvent enriches a cilium/ebpf capability event
// ANCHOR: Capability event enrichment with privilege escalation context - Phase 2, Dec 26, 2025
// Migrated from goBPF to cilium/ebpf with reflection-based field extraction - Dec 27, 2025
// Populates privilege escalation and capability restriction fields; uses interface{} to avoid circular imports
func (e *Enricher) EnrichCapabilityEvent(
	ctx context.Context,
	rawEvent interface{},
) (*EnrichedEvent, error) {
	if e.K8sClient != nil {
		var cancel context.CancelFunc
		ctx, cancel = withEnrichmentTimeout(ctx, enrichmentK8sTimeout)
		defer cancel()
	}

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
	cgroupIDVal := fieldUintValue(v, "CgroupID")

	// ANCHOR: Container context propagation - Feature: PID-based container lookup - Jan 2026
	// Resolve container metadata from PID when available
	containerID := procContainerID(pidVal)
	containerCtx := &ContainerContext{
		ContainerID: containerID,
	}
	podMeta, err := e.getPodMetadata(ctx, containerID, cgroupIDVal)
	if err != nil {
		return nil, err
	}

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
		if podMeta.OwnerRef != nil {
			k8sCtx.OwnerRef = &OwnerReference{
				Kind: podMeta.OwnerRef.Kind,
				Name: podMeta.OwnerRef.Name,
				UID:  podMeta.OwnerRef.UID,
			}
		}
		k8sCtx.AuditLoggingEnabled = podMeta.AuditLoggingEnabled
		containerCtx.ContainerName = podMeta.ContainerName
		// ANCHOR: Compliance fields for capability events - Feature: image/volume/kernel signals - Mar 22, 2026
		// Propagates pod-derived compliance signals into capability events for rule evaluation.
		applyPodComplianceFields(containerCtx, podMeta)
	}

	// Build container context with capability defaults
	containerCtx.RunAsRoot = uidVal == 0
	containerCtx.AllowPrivilegeEscalation = true // Default to true (least restrictive)
	containerCtx.Privileged = false              // Default to false

	enriched := &EnrichedEvent{
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
	}

	// ANCHOR: K8s-native filter - Requirement: discard host events - Mar 24, 2026
	// Return sentinel so the agent can decide (per kubernetes_only config) whether to discard.
	if k8sCtx.PodUID == "" {
		return enriched, ErrNoKubernetesContext
	}

	return enriched, nil
}
