package enrichment

import "errors"

// ANCHOR: Sentinel: no Kubernetes pod context - Filter: host event discard - Mar 24, 2026
// ErrNoKubernetesContext is returned by Enrich* methods when the event's PID belongs
// to a host process with no cgroup container ID or no matching K8s pod.
// When enrichment.kubernetes_only=true the agent discards such events.
var ErrNoKubernetesContext = errors.New("no kubernetes pod context: event is not from a pod")
