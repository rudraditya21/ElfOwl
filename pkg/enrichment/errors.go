package enrichment

import "errors"

// ANCHOR: Sentinel: no Kubernetes pod context - Filter: host event discard - Mar 24, 2026
// ErrNoKubernetesContext is returned by Enrich* methods when the event's PID belongs
// to a host process with no cgroup container ID or no matching K8s pod.
// When enrichment.kubernetes_only=true the agent discards such events.
var ErrNoKubernetesContext = errors.New("no kubernetes pod context: event is not from a pod")

// ANCHOR: ErrFilePathFiltered - Bug: path filter bypassed when kubernetes_only=false - May 1, 2026
// Returned by EnrichFileEvent when the file path does not satisfy watch_paths/ignore_paths.
// Unlike ErrNoKubernetesContext, this error always causes the event to be discarded —
// kubernetes_only=false must not override an explicit operator path filter.
var ErrFilePathFiltered = errors.New("file event dropped by path filter")
