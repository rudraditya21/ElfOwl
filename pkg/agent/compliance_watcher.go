// ANCHOR: K8s compliance watcher - Feature: pod_spec_check + network_policy_check - Mar 22, 2026
// Watches Kubernetes API objects and emits compliance events that are not driven
// by eBPF runtime telemetry.

package agent

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/kubernetes"
)

func (a *Agent) startComplianceWatchers(ctx context.Context) {
	if a.K8sClient == nil || a.K8sClient.GetClientset() == nil {
		a.Logger.Warn("kubernetes client unavailable; skipping compliance watchers")
		return
	}

	resync := a.Config.Agent.Kubernetes.WatchInterval
	if resync < 0 {
		resync = 0
	}

	ready := make(chan struct{})
	factory := informers.NewSharedInformerFactory(a.K8sClient.GetClientset(), resync)
	podInformer := factory.Core().V1().Pods().Informer()
	netpolInformer := factory.Networking().V1().NetworkPolicies().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			a.onPodEvent(ctx, obj, ready)
		},
		UpdateFunc: func(_, newObj interface{}) {
			a.onPodEvent(ctx, newObj, ready)
		},
	})

	netpolInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			a.onNetworkPolicyEvent(ctx, obj, ready)
		},
		UpdateFunc: func(_, newObj interface{}) {
			a.onNetworkPolicyEvent(ctx, newObj, ready)
		},
	})

	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced, netpolInformer.HasSynced) {
		a.Logger.Warn("compliance watchers cache sync failed")
		return
	}

	// ANCHOR: Cache sync gate for compliance events - Safety: avoid pre-sync emissions - Mar 22, 2026
	close(ready)
	a.Logger.Info("compliance watchers started")
	<-ctx.Done()
	a.Logger.Info("compliance watchers stopped")
}

func (a *Agent) onPodEvent(ctx context.Context, obj interface{}, ready <-chan struct{}) {
	if !complianceReady(ready) {
		return
	}

	pod := podFromObject(obj)
	if pod == nil {
		return
	}

	// ANCHOR: Running-only pod compliance events - Signal: avoid terminal/pending noise - Mar 22, 2026
	if !shouldProcessPod(pod) {
		return
	}

	// ANCHOR: Multi-container pod_spec_check events - Bugfix: per-container compliance - Mar 22, 2026
	events := a.buildPodSpecEvents(ctx, pod)
	for _, event := range events {
		a.handleComplianceEvent(ctx, event)
	}
}

func (a *Agent) onNetworkPolicyEvent(ctx context.Context, obj interface{}, ready <-chan struct{}) {
	if !complianceReady(ready) {
		return
	}

	netpol := networkPolicyFromObject(obj)
	if netpol == nil {
		return
	}

	hasDefaultDeny := false
	if a.K8sClient != nil {
		hasDefaultDeny = a.K8sClient.CheckNamespaceDefaultDenyPolicy(ctx, netpol.Namespace)
	}

	event := a.buildNetworkPolicyEvent(netpol, hasDefaultDeny)

	a.handleComplianceEvent(ctx, event)
}

// ANCHOR: Pod spec compliance event builder - Feature: CIS pod_spec_check - Mar 22, 2026
// Extracts security context and resource settings from pod specs for CIS rules.
func (a *Agent) buildPodSpecEvents(ctx context.Context, pod *corev1.Pod) []*enrichment.EnrichedEvent {
	if pod == nil || len(pod.Spec.Containers) == 0 {
		return nil
	}

	serviceAccount := a.resolveServiceAccount(ctx, pod)

	events := make([]*enrichment.EnrichedEvent, 0, len(pod.Spec.Containers))
	for _, container := range pod.Spec.Containers {
		event := a.buildPodSpecEventForContainer(pod, container, serviceAccount)
		if event != nil {
			events = append(events, event)
		}
	}
	return events
}

func (a *Agent) buildPodSpecEventForContainer(pod *corev1.Pod, container corev1.Container, serviceAccount *corev1.ServiceAccount) *enrichment.EnrichedEvent {
	if pod == nil {
		return nil
	}

	containerName := container.Name
	image := container.Image
	imagePullPolicy := "IfNotPresent"
	if container.ImagePullPolicy != "" {
		imagePullPolicy = string(container.ImagePullPolicy)
	}

	seccompProfile := securityContextSeccomp(pod, container)
	apparmorProfile := apparmorProfile(pod, containerName)
	selinuxLevel := securityContextSELinux(pod, container)

	allowPrivilegeEscalation := true
	if container.SecurityContext != nil && container.SecurityContext.AllowPrivilegeEscalation != nil {
		allowPrivilegeEscalation = *container.SecurityContext.AllowPrivilegeEscalation
	}

	privileged := false
	if container.SecurityContext != nil && container.SecurityContext.Privileged != nil {
		privileged = *container.SecurityContext.Privileged
	}

	readOnlyRootFilesystem := false
	if container.SecurityContext != nil && container.SecurityContext.ReadOnlyRootFilesystem != nil {
		readOnlyRootFilesystem = *container.SecurityContext.ReadOnlyRootFilesystem
	}

	runAsNonRoot := securityContextRunAsNonRoot(pod, container)
	runAsUser := securityContextRunAsUser(pod, container)
	runAsRoot := resolveRunAsRoot(runAsNonRoot, runAsUser)

	memoryLimit, cpuLimit := resourceLimits(container)
	memoryRequest, cpuRequest, storageRequest := resourceRequests(container)

	serviceAccount := pod.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}

	k8sCtx := &enrichment.K8sContext{
		ClusterID:      a.Config.Agent.ClusterID,
		NodeName:       a.Config.Agent.NodeName,
		Namespace:      pod.Namespace,
		PodName:        pod.Name,
		PodUID:         string(pod.UID),
		ServiceAccount: serviceAccount,
		Image:          image,
		ImageRegistry:  parseImageRegistry(image),
		ImageTag:       parseImageTag(image),
		Labels:         pod.Labels,
	}

	if pod.Spec.AutomountServiceAccountToken != nil {
		k8sCtx.AutomountServiceAccountToken = *pod.Spec.AutomountServiceAccountToken
	}

	if len(pod.OwnerReferences) > 0 {
		owner := pod.OwnerReferences[0]
		k8sCtx.OwnerRef = &enrichment.OwnerReference{
			Kind: owner.Kind,
			Name: owner.Name,
			UID:  string(owner.UID),
		}
	}

	imageScanStatus := kubernetes.ImageScanStatusFromPod(pod, containerName)
	imageSigned := false
	if signed, ok := kubernetes.ImageSignedFromPod(pod, containerName); ok {
		imageSigned = signed
	}
	imageRegistryAuth := kubernetes.ImageRegistryAuthFromPod(pod, containerName, serviceAccount)
	volumeType := kubernetes.VolumeTypeForContainer(pod, container)
	kernelHardening := kubernetes.KernelHardeningFromPod(pod)

	containerCtx := &enrichment.ContainerContext{
		ContainerName:            containerName,
		Privileged:               privileged,
		RunAsRoot:                runAsRoot,
		AllowPrivilegeEscalation: allowPrivilegeEscalation,
		ReadOnlyFilesystem:       readOnlyRootFilesystem,
		HostNetwork:              pod.Spec.HostNetwork,
		HostIPC:                  pod.Spec.HostIPC,
		HostPID:                  pod.Spec.HostPID,
		SeccompProfile:           seccompProfile,
		ApparmorProfile:          apparmorProfile,
		SELinuxLevel:             selinuxLevel,
		ImagePullPolicy:          imagePullPolicy,
		MemoryLimit:              memoryLimit,
		CPULimit:                 cpuLimit,
		MemoryRequest:            memoryRequest,
		CPURequest:               cpuRequest,
		StorageRequest:           storageRequest,
		// ANCHOR: Compliance fields for pod_spec_check - Feature: image/volume/kernel signals - Mar 22, 2026
		// Populate CIS control inputs from pod annotations, imagePullSecrets, volume mounts, and sysctls.
		ImageScanStatus:   imageScanStatus,
		ImageRegistryAuth: imageRegistryAuth,
		ImageSigned:       imageSigned,
		VolumeType:        volumeType,
		KernelHardening:   kernelHardening,
	}

	return &enrichment.EnrichedEvent{
		EventType:  "pod_spec_check",
		Timestamp:  time.Now(),
		Kubernetes: k8sCtx,
		Container:  containerCtx,
	}
}

func (a *Agent) buildNetworkPolicyEvent(netpol *networkingv1.NetworkPolicy, hasDefaultDeny bool) *enrichment.EnrichedEvent {
	if netpol == nil {
		return nil
	}

	return &enrichment.EnrichedEvent{
		EventType: "network_policy_check",
		Timestamp: time.Now(),
		Kubernetes: &enrichment.K8sContext{
			ClusterID:                   a.Config.Agent.ClusterID,
			NodeName:                    a.Config.Agent.NodeName,
			Namespace:                   netpol.Namespace,
			HasDefaultDenyNetworkPolicy: hasDefaultDeny,
		},
	}
}

func podFromObject(obj interface{}) *corev1.Pod {
	switch typed := obj.(type) {
	case *corev1.Pod:
		return typed
	case cache.DeletedFinalStateUnknown:
		if pod, ok := typed.Obj.(*corev1.Pod); ok {
			return pod
		}
	}
	return nil
}

func networkPolicyFromObject(obj interface{}) *networkingv1.NetworkPolicy {
	switch typed := obj.(type) {
	case *networkingv1.NetworkPolicy:
		return typed
	case cache.DeletedFinalStateUnknown:
		if netpol, ok := typed.Obj.(*networkingv1.NetworkPolicy); ok {
			return netpol
		}
	}
	return nil
}

// ANCHOR: Service account lookup for registry auth - Feature: CIS_4.3.5 inputs - Mar 22, 2026
// Retrieves ServiceAccount imagePullSecrets when pod-level secrets are absent.
func (a *Agent) resolveServiceAccount(ctx context.Context, pod *corev1.Pod) *corev1.ServiceAccount {
	if pod == nil || a.K8sClient == nil || a.K8sClient.GetClientset() == nil {
		return nil
	}

	serviceAccountName := pod.Spec.ServiceAccountName
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}

	serviceAccount, err := a.K8sClient.GetClientset().CoreV1().ServiceAccounts(pod.Namespace).Get(ctx, serviceAccountName, metav1.GetOptions{})
	if err != nil {
		return nil
	}

	return serviceAccount
}

func apparmorProfile(pod *corev1.Pod, containerName string) string {
	if pod == nil || containerName == "" || pod.Annotations == nil {
		return ""
	}
	key := "container.apparmor.security.beta.kubernetes.io/" + containerName
	return pod.Annotations[key]
}

func securityContextSeccomp(pod *corev1.Pod, container corev1.Container) string {
	if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
		return string(container.SecurityContext.SeccompProfile.Type)
	}
	if pod != nil && pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
		return string(pod.Spec.SecurityContext.SeccompProfile.Type)
	}
	return ""
}

func securityContextSELinux(pod *corev1.Pod, container corev1.Container) string {
	if container.SecurityContext != nil && container.SecurityContext.SELinuxOptions != nil {
		return container.SecurityContext.SELinuxOptions.Level
	}
	if pod != nil && pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SELinuxOptions != nil {
		return pod.Spec.SecurityContext.SELinuxOptions.Level
	}
	return ""
}

func securityContextRunAsNonRoot(pod *corev1.Pod, container corev1.Container) bool {
	if container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil {
		return *container.SecurityContext.RunAsNonRoot
	}
	if pod != nil && pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
		return *pod.Spec.SecurityContext.RunAsNonRoot
	}
	return false
}

func securityContextRunAsUser(pod *corev1.Pod, container corev1.Container) *int64 {
	if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil {
		return container.SecurityContext.RunAsUser
	}
	if pod != nil && pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil {
		return pod.Spec.SecurityContext.RunAsUser
	}
	return nil
}

func resolveRunAsRoot(runAsNonRoot bool, runAsUser *int64) bool {
	if runAsNonRoot {
		return false
	}
	if runAsUser == nil {
		return true
	}
	return *runAsUser == 0
}

func resourceLimits(container corev1.Container) (string, string) {
	memoryLimit := ""
	cpuLimit := ""
	if container.Resources.Limits == nil {
		return memoryLimit, cpuLimit
	}
	if mem, ok := container.Resources.Limits[corev1.ResourceMemory]; ok {
		memoryLimit = mem.String()
	}
	if cpu, ok := container.Resources.Limits[corev1.ResourceCPU]; ok {
		cpuLimit = cpu.String()
	}
	return memoryLimit, cpuLimit
}

func resourceRequests(container corev1.Container) (string, string, string) {
	memoryRequest := ""
	cpuRequest := ""
	storageRequest := ""
	if container.Resources.Requests == nil {
		return memoryRequest, cpuRequest, storageRequest
	}
	if mem, ok := container.Resources.Requests[corev1.ResourceMemory]; ok {
		memoryRequest = mem.String()
	}
	if cpu, ok := container.Resources.Requests[corev1.ResourceCPU]; ok {
		cpuRequest = cpu.String()
	}
	if storage, ok := container.Resources.Requests[corev1.ResourceEphemeralStorage]; ok {
		storageRequest = storage.String()
	}
	return memoryRequest, cpuRequest, storageRequest
}

func parseImageRegistry(image string) string {
	if image == "" {
		return ""
	}
	parts := strings.Split(image, "/")
	if len(parts) > 1 && strings.Contains(parts[0], ".") {
		return parts[0]
	}
	return "docker.io"
}

func parseImageTag(image string) string {
	if image == "" {
		return ""
	}
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[idx+1:]
	}
	return "latest"
}

func complianceReady(ready <-chan struct{}) bool {
	if ready == nil {
		return true
	}
	select {
	case <-ready:
		return true
	default:
		return false
	}
}

func shouldProcessPod(pod *corev1.Pod) bool {
	return pod != nil && pod.Status.Phase == corev1.PodRunning
}
