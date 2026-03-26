# Kubernetes-Only Event Filtering

## Overview

elf-owl is a Kubernetes-native compliance observer (see [REQUIREMENT.md](REQUIREMENT.md)). eBPF probes fire on ALL host PIDs, but host-process events carry no pod context and should not reach the CIS rule engine.

The `enrichment.kubernetes_only` flag (default: `true`) enforces this at the enrichment stage.

## How It Works

Each `Enrich*` method in `pkg/enrichment/enricher.go` calls `procContainerID(pid)` to extract a cgroup container ID, then looks up the matching K8s pod. If `K8sContext.PodUID` is empty after that lookup (host process or unknown container), the method returns `ErrNoKubernetesContext` instead of a populated `EnrichedEvent`.

The agent's `handle*Events` functions check for this sentinel and either discard the event (default) or fall back to partial enrichment (opt-out).

## Configuration

```yaml
enrichment:
  kubernetes_only: true   # default; omitting has the same effect
```

Set `false` for bare-metal deployments or mixed host+container monitoring.

Override at runtime: `OWL_KUBERNETES_ONLY=false`

## Behaviour Table

| `kubernetes_only` | Pod found | Outcome |
|-------------------|-----------|---------|
| `true` (default)  | yes       | enriched event → rule engine |
| `true` (default)  | no        | discarded; `host_events_discarded` counter +1 |
| `false`           | yes       | enriched event → rule engine |
| `false`           | no        | partial event (monitor data only) → rule engine |

## Metrics

`host_events_discarded` (atomic counter) — increments each time an event is discarded because `kubernetes_only=true` and no pod context was found.

Exposed in the existing `GetStats()` / Prometheus scrape alongside `enrichment_errors`.

## Rationale

### Why Kubernetes-native by default?

elf-owl's requirement states:
> "Kubernetes context required: compliance evaluation depends on pod and policy metadata."

Host processes have neither pod labels, service account identity, nor network policy associations. Running CIS rules against them produces false positives. For example:
- **CIS 4.1.5** (restrict memory to 512Mi) has no meaning for host processes with unbounded memory.
- **CIS 4.6.1** (deny all traffic) cannot be evaluated without network policy context.
- **CIS 4.2.6** (read-only root FS) cannot be checked against `/` on the host.

By default, elf-owl discards these events at the enrichment stage, keeping the signal clean.

### Why allow an opt-out?

Some deployments run elf-owl on bare-metal or mixed host+container systems where host-process monitoring is intentional. The `kubernetes_only=false` escape hatch preserves host event visibility in those cases, falling back to partial enrichment from the eBPF monitors.

## Examples

### Kubernetes-native mode (default)

```bash
# Start with kubernetes_only=true (implicit)
$ kubectl create configmap elf-owl-config --from-file=config/elf-owl.yaml

# Host process 'ls' on node:
$ ls
# Agent logs: "discarded host process event: no pod context"
# host_events_discarded counter: +1
# Rule engine: never sees the event

# Pod exec into a container:
$ kubectl exec -it pod/my-app -- sh
# Agent logs: "enriched process event" (K8s context found)
# Rule engine: evaluates CIS controls
```

### Mixed host+container monitoring (opt-out)

```bash
# Override at runtime
export OWL_KUBERNETES_ONLY=false
$ ./start-agent.sh

# Host process 'ls' on node:
$ ls
# Agent logs: "processing host process event (kubernetes_only disabled)"
# Partial enrichment: {PID: 123, Command: "ls", ...}  (no K8s fields)
# Rule engine: evaluates with partial context (may produce different results)
```

## Troubleshooting

### All events discarded (kubernetes_only=true)

**Symptom**: `host_events_discarded` counter increasing, no violations ever found.

**Debug**:
```bash
# 1. Verify K8s API is reachable
kubectl logs -n elf-owl-system -l app=elf-owl | grep -i "kubernetes\|api"

# 2. Check for K8s client errors
kubectl logs -n elf-owl-system -l app=elf-owl | grep -i "error.*cgroup\|error.*pod"

# 3. Temporarily set kubernetes_only=false and re-run tests
export OWL_KUBERNETES_ONLY=false
```
