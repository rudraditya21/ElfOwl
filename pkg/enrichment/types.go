// ANCHOR: Event enrichment data structures - Dec 26, 2025
// Defines enriched event types with Kubernetes and container context

package enrichment

import (
	"time"

	"github.com/udyansh/elf-owl/pkg/kubernetes"
)

// EnrichedEvent is an event with added K8s, container, and runtime context
type EnrichedEvent struct {
	// Original cilium/ebpf event (interface{} to avoid circular import)
	RawEvent  interface{} `json:"raw_event"`
	EventType string      `json:"event_type"`

	// Kubernetes context
	Kubernetes *K8sContext `json:"kubernetes"`

	// Container context
	Container *ContainerContext `json:"container"`

	// Process/file/capability context (populated where applicable)
	Process    *ProcessContext    `json:"process"`
	File       *FileContext       `json:"file"`
	Capability *CapabilityContext `json:"capability"`

	// Network and DNS context
	Network *NetworkContext `json:"network"`
	DNS     *DNSContext     `json:"dns"`

	// Derived fields
	Timestamp  time.Time `json:"timestamp"`
	Severity   string    `json:"severity"`
	CISControl string    `json:"cis_control"`
}

// K8sContext contains Kubernetes metadata
type K8sContext struct {
	ClusterID                    string            `json:"cluster_id"`
	NodeName                     string            `json:"node_name"`
	Namespace                    string            `json:"namespace"`
	PodName                      string            `json:"pod_name"`
	PodUID                       string            `json:"pod_uid"`
	ServiceAccount               string            `json:"service_account"`
	Image                        string            `json:"image"`
	ImageRegistry                string            `json:"image_registry"`
	ImageTag                     string            `json:"image_tag"`
	Labels                       map[string]string `json:"labels"`
	OwnerRef                     *OwnerReference   `json:"owner_ref"`
	AutomountServiceAccountToken bool              `json:"automount_service_account_token"`
	HasDefaultDenyNetworkPolicy  bool              `json:"has_default_deny_network_policy"`
	// ANCHOR: Extended K8s fields for Phase 1 RBAC controls - Dec 26, 2025
	RBACEnforced              bool  `json:"rbac_enforced"`
	RBACLevel                 int   `json:"rbac_level"`
	ServiceAccountTokenAge    int64 `json:"service_account_token_age"`
	ServiceAccountPermissions int   `json:"service_account_permissions"`
	RBACPolicyDefined         bool  `json:"rbac_policy_defined"`
	RolePermissionCount       int   `json:"role_permission_count"`
	AuditLoggingEnabled       bool  `json:"audit_logging_enabled"`
}

// OwnerReference identifies the owner of a pod
type OwnerReference struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// ContainerContext contains container runtime metadata
type ContainerContext struct {
	ContainerID   string            `json:"container_id"`
	Runtime       string            `json:"runtime"`
	ContainerName string            `json:"container_name"`
	Labels        map[string]string `json:"labels"`
	Privileged    bool              `json:"privileged"`
	RunAsRoot     bool              `json:"run_as_root"`
	// ANCHOR: Extended security context fields for Phase 1 - Dec 26, 2025
	AllowPrivilegeEscalation bool   `json:"allow_privilege_escalation"`
	HostNetwork              bool   `json:"host_network"`
	HostIPC                  bool   `json:"host_ipc"`
	HostPID                  bool   `json:"host_pid"`
	SeccompProfile           string `json:"seccomp_profile"`
	ApparmorProfile          string `json:"apparmor_profile"`
	SELinuxLevel             string `json:"selinux_level"`
	ImagePullPolicy          string `json:"image_pull_policy"`
	ImageScanStatus          string `json:"image_scan_status"`
	ImageRegistryAuth        bool   `json:"image_registry_auth"`
	ImageSigned              bool   `json:"image_signed"`
	MemoryLimit              string `json:"memory_limit"`
	CPULimit                 string `json:"cpu_limit"`
	MemoryRequest            string `json:"memory_request"`
	CPURequest               string `json:"cpu_request"`
	StorageRequest           string `json:"storage_request"`
	ReadOnlyFilesystem       bool   `json:"read_only_filesystem"`
	VolumeType               string `json:"volume_type"`
	IsolationLevel           int    `json:"isolation_level"`
	KernelHardening          bool   `json:"kernel_hardening"`
}

// ProcessContext captures process metadata from cilium/ebpf events
// ANCHOR: Process context extensions - Feature: parent PID + arguments - Jan 2026
// Adds parent PID and argument list for richer forensic context.
type ProcessContext struct {
	PID         uint32   `json:"pid"`
	ParentPID   uint32   `json:"parent_pid"`
	UID         uint32   `json:"uid"`
	GID         uint32   `json:"gid"`
	Command     string   `json:"command"`
	Arguments   []string `json:"arguments"`
	Filename    string   `json:"filename"`
	ContainerID string   `json:"container_id"`
}

// FileContext captures file metadata from cilium/ebpf events
type FileContext struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
}

// CapabilityContext captures capability usage metadata
type CapabilityContext struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
	PID     uint32 `json:"pid"`
	UID     uint32 `json:"uid"`
}

// Note: PodMetadata and NodeMetadata are defined in kubernetes package
// to avoid circular imports. We import and re-export them here for convenience.

// Type aliases to kubernetes types to avoid duplication
type PodMetadata = kubernetes.PodMetadata
type NodeMetadata = kubernetes.NodeMetadata

// ANCHOR: Network and DNS contexts for Phase 1 - Dec 26, 2025
// Support for network policy and DNS rule matching

// NetworkContext captures network metadata from cilium/ebpf events
type NetworkContext struct {
	SourceIP           string `json:"source_ip"`
	DestinationIP      string `json:"destination_ip"`
	SourcePort         uint16 `json:"source_port"`
	DestinationPort    uint16 `json:"destination_port"`
	Protocol           string `json:"protocol"`
	Direction          string `json:"direction"` // inbound, outbound
	ConnectionState    string `json:"connection_state"`
	NetworkNamespaceID uint32 `json:"network_namespace_id"`
	IngressRestricted  bool   `json:"ingress_restricted"`
	EgressRestricted   bool   `json:"egress_restricted"`
	NamespaceIsolation bool   `json:"namespace_isolation"`
}

// DNSContext captures DNS query metadata from cilium/ebpf events
type DNSContext struct {
	QueryName      string   `json:"query_name"`
	QueryType      string   `json:"query_type"` // A, AAAA, MX, etc.
	ResponseCode   int      `json:"response_code"`
	QueryAllowed   bool     `json:"query_allowed"`
	AllowedDomains []string `json:"allowed_domains"`
}
