// ANCHOR: Pod compliance field extraction - Feature: image/volume/kernel signals - Mar 22, 2026
// Centralizes pod-spec derived signals used by CIS compliance fields.

package kubernetes

import (
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	imageScanStatusKey   = "image-scan-status"
	imageSignedKey       = "image-signed"
	imageRegistryAuthKey = "image-registry-auth"
	containerRuntimeKey  = "container-runtime"
	isolationLevelKey    = "container-isolation-level"
	auditLoggingKey      = "audit-logging-enabled"
)

var sensitiveVolumeTypes = []string{"hostPath", "local", "emptyDir"}

// ANCHOR: Image scan status extraction - Feature: CIS_4.3.4 inputs - Mar 22, 2026
// Reads scan status from pod annotations/labels; defaults to "unknown" when not provided.
func ImageScanStatusFromPod(pod *corev1.Pod, containerName string) string {
	if pod == nil {
		return ""
	}
	if value, ok := podStringValue(pod, imageScanStatusKey, containerName); ok {
		return value
	}
	return "unknown"
}

// ANCHOR: Image signature extraction - Feature: CIS_4.3.6 inputs - Mar 22, 2026
// Reads signature verification state from pod annotations/labels when present.
func ImageSignedFromPod(pod *corev1.Pod, containerName string) (bool, bool) {
	if pod == nil {
		return false, false
	}
	value, ok := podStringValue(pod, imageSignedKey, containerName)
	if !ok {
		return false, false
	}
	return parseBoolValue(value)
}

// ANCHOR: Registry auth detection - Feature: CIS_4.3.5 inputs - Mar 22, 2026
// Prefers explicit annotation/label overrides, then falls back to imagePullSecrets.
func ImageRegistryAuthFromPod(pod *corev1.Pod, containerName string, serviceAccount *corev1.ServiceAccount) bool {
	if pod == nil {
		return false
	}
	if override, ok := podBoolValue(pod, imageRegistryAuthKey, containerName); ok {
		return override
	}
	if len(pod.Spec.ImagePullSecrets) > 0 {
		return true
	}
	if serviceAccount != nil && len(serviceAccount.ImagePullSecrets) > 0 {
		return true
	}
	return false
}

// ANCHOR: Volume type resolution - Feature: CIS_4.8.2 inputs - Mar 22, 2026
// Determines the most sensitive mounted volume type for a specific container.
func VolumeTypeForContainer(pod *corev1.Pod, container corev1.Container) string {
	if pod == nil || len(container.VolumeMounts) == 0 {
		return ""
	}

	volumeTypes := make(map[string]string, len(pod.Spec.Volumes))
	for _, volume := range pod.Spec.Volumes {
		volumeTypes[volume.Name] = volumeSourceType(volume)
	}

	mountedTypes := make(map[string]bool)
	firstType := ""
	for _, mount := range container.VolumeMounts {
		volumeType := volumeTypes[mount.Name]
		if volumeType == "" {
			continue
		}
		if firstType == "" {
			firstType = volumeType
		}
		mountedTypes[volumeType] = true
	}

	for _, sensitive := range sensitiveVolumeTypes {
		if mountedTypes[sensitive] {
			return sensitive
		}
	}

	return firstType
}

// ANCHOR: Kernel hardening detection - Feature: CIS_4.9.3 inputs - Mar 22, 2026
// Uses sysctl settings on pod security context to signal kernel hardening.
func KernelHardeningFromPod(pod *corev1.Pod) bool {
	if pod == nil || pod.Spec.SecurityContext == nil {
		return false
	}

	for _, sysctl := range pod.Spec.SecurityContext.Sysctls {
		name := strings.TrimSpace(sysctl.Name)
		value := strings.TrimSpace(sysctl.Value)
		switch name {
		case "kernel.dmesg_restrict":
			if value == "1" {
				return true
			}
		case "kernel.kptr_restrict":
			if value == "1" {
				return true
			}
		case "kernel.yama.ptrace_scope":
			if numeric, err := strconv.Atoi(value); err == nil && numeric >= 1 {
				return true
			}
		}
	}

	return false
}

// ANCHOR: Container runtime extraction - Feature: CIS_4.9.1 inputs - Mar 29, 2026
// Reads runtime from annotations/labels first, then container status ID prefixes.
func ContainerRuntimeFromPod(pod *corev1.Pod, containerName string) string {
	if pod == nil {
		return ""
	}
	if value, ok := podStringValue(pod, containerRuntimeKey, containerName); ok && value != "" {
		return strings.ToLower(value)
	}

	if runtime := runtimeFromStatuses(pod.Status.ContainerStatuses, containerName); runtime != "" {
		return runtime
	}
	if runtime := runtimeFromStatuses(pod.Status.InitContainerStatuses, containerName); runtime != "" {
		return runtime
	}
	if runtime := runtimeFromStatuses(pod.Status.EphemeralContainerStatuses, containerName); runtime != "" {
		return runtime
	}

	return "unknown"
}

// ANCHOR: Isolation level derivation - Feature: CIS_4.9.2 inputs - Mar 29, 2026
// Computes a coarse isolation score from pod/container security settings.
func IsolationLevelForContainer(pod *corev1.Pod, container corev1.Container) int {
	if pod == nil {
		return 0
	}

	// Explicit override for clusters with custom isolation policies.
	if value, ok := podStringValue(pod, isolationLevelKey, container.Name); ok {
		if parsed, err := strconv.Atoi(value); err == nil {
			switch {
			case parsed < 0:
				return 0
			case parsed > 3:
				return 3
			default:
				return parsed
			}
		}
	}

	score := 0

	// Strong signals.
	if runAsNonRootForContainer(pod, container) {
		score += 2
	}
	if privilegeEscalationDisabled(container) {
		score++
	}
	if readOnlyRootFS(container) {
		score++
	}

	// Additional hardening signals.
	if !privilegedContainer(container) {
		score++
	}
	if seccomp := seccompProfileForContainer(pod, container); seccomp != "" && strings.ToLower(seccomp) != "unconfined" {
		score++
	}
	if !pod.Spec.HostNetwork && !pod.Spec.HostIPC && !pod.Spec.HostPID {
		score++
	}

	switch {
	case score >= 6:
		return 3
	case score >= 4:
		return 2
	case score >= 2:
		return 1
	default:
		return 0
	}
}

// ANCHOR: Audit logging override extraction - Feature: CIS_5.5.1 inputs - Mar 29, 2026
// Allows explicit per-pod/namespace override via annotations or labels.
func AuditLoggingEnabledFromPod(pod *corev1.Pod) (bool, bool) {
	if pod == nil {
		return false, false
	}
	return podBoolValue(pod, auditLoggingKey, "")
}

// ANCHOR: Projected service-account token TTL extraction - Feature: CIS_5.2.2 inputs - Mar 29, 2026
// Returns the maximum projected token expirationSeconds found on pod volumes.
// This provides a non-zero token lifetime signal on K8s 1.22+ where legacy SA secrets are absent.
func ServiceAccountTokenTTLFromPod(pod *corev1.Pod) int64 {
	if pod == nil {
		return 0
	}

	var maxTTL int64
	for _, volume := range pod.Spec.Volumes {
		if volume.Projected == nil {
			continue
		}
		for _, source := range volume.Projected.Sources {
			if source.ServiceAccountToken == nil {
				continue
			}
			// Kubernetes defaults projected token expiration to 3600 seconds when unset.
			ttl := int64(3600)
			if source.ServiceAccountToken.ExpirationSeconds != nil && *source.ServiceAccountToken.ExpirationSeconds > 0 {
				ttl = *source.ServiceAccountToken.ExpirationSeconds
			}
			if ttl > maxTTL {
				maxTTL = ttl
			}
		}
	}

	return maxTTL
}

// ANCHOR: Annotation/label lookup helper - Utility: container-scoped keys - Mar 22, 2026
// Checks annotations/labels for base and container-qualified keys.
func podStringValue(pod *corev1.Pod, baseKey, containerName string) (string, bool) {
	keys := annotationKeys(baseKey, containerName)
	for _, key := range keys {
		if value, ok := pod.Annotations[key]; ok {
			return strings.TrimSpace(value), true
		}
	}
	for _, key := range keys {
		if value, ok := pod.Labels[key]; ok {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// ANCHOR: Boolean annotation parsing - Utility: typed compliance flags - Mar 22, 2026
// Parses boolean values from annotations/labels for compliance fields.
func podBoolValue(pod *corev1.Pod, baseKey, containerName string) (bool, bool) {
	value, ok := podStringValue(pod, baseKey, containerName)
	if !ok {
		return false, false
	}
	return parseBoolValue(value)
}

// ANCHOR: Container-specific annotation keys - Utility: flexible key formats - Mar 22, 2026
// Supports base, dotted, and slash-qualified container keys.
func annotationKeys(baseKey, containerName string) []string {
	keys := []string{baseKey}
	if containerName == "" {
		return keys
	}
	keys = append(keys, baseKey+"."+containerName)
	keys = append(keys, baseKey+"/"+containerName)
	return keys
}

// ANCHOR: Boolean value normalization - Utility: annotation parsing - Mar 22, 2026
// Accepts common truthy/falsey strings including signed/unsigned.
func parseBoolValue(value string) (bool, bool) {
	normalized := strings.TrimSpace(strings.ToLower(value))
	switch normalized {
	case "true", "1", "yes", "y", "signed":
		return true, true
	case "false", "0", "no", "n", "unsigned":
		return false, true
	default:
		return false, false
	}
}

// ANCHOR: Volume source classification - Utility: volume type mapping - Mar 22, 2026
// Maps Kubernetes volume sources to normalized type strings.
func volumeSourceType(volume corev1.Volume) string {
	switch {
	case volume.HostPath != nil:
		return "hostPath"
	case volume.EmptyDir != nil:
		return "emptyDir"
	case volume.PersistentVolumeClaim != nil:
		return "persistentVolumeClaim"
	case volume.ConfigMap != nil:
		return "configMap"
	case volume.Secret != nil:
		return "secret"
	case volume.Projected != nil:
		return "projected"
	case volume.DownwardAPI != nil:
		return "downwardAPI"
	case volume.CSI != nil:
		return "csi"
	case volume.Ephemeral != nil:
		return "ephemeral"
	default:
		return ""
	}
}

func runtimeFromStatuses(statuses []corev1.ContainerStatus, containerName string) string {
	for _, status := range statuses {
		if containerName != "" && status.Name != containerName {
			continue
		}
		if runtime := runtimeFromContainerID(status.ContainerID); runtime != "" {
			return runtime
		}
	}
	return ""
}

func runtimeFromContainerID(containerID string) string {
	if containerID == "" {
		return ""
	}
	parts := strings.SplitN(containerID, "://", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

func runAsNonRootForContainer(pod *corev1.Pod, container corev1.Container) bool {
	if container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil {
		return *container.SecurityContext.RunAsNonRoot
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
		return *pod.Spec.SecurityContext.RunAsNonRoot
	}
	return false
}

func privilegeEscalationDisabled(container corev1.Container) bool {
	return container.SecurityContext != nil &&
		container.SecurityContext.AllowPrivilegeEscalation != nil &&
		!*container.SecurityContext.AllowPrivilegeEscalation
}

func readOnlyRootFS(container corev1.Container) bool {
	return container.SecurityContext != nil &&
		container.SecurityContext.ReadOnlyRootFilesystem != nil &&
		*container.SecurityContext.ReadOnlyRootFilesystem
}

func privilegedContainer(container corev1.Container) bool {
	return container.SecurityContext != nil &&
		container.SecurityContext.Privileged != nil &&
		*container.SecurityContext.Privileged
}

func seccompProfileForContainer(pod *corev1.Pod, container corev1.Container) string {
	if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
		return string(container.SecurityContext.SeccompProfile.Type)
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
		return string(pod.Spec.SecurityContext.SeccompProfile.Type)
	}
	return ""
}
