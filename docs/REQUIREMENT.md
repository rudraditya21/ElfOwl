# elf-owl Requirement and Role in Kubernetes

**Purpose:** Define why elf-owl is needed, what role it plays, and what boundaries it enforces.

elf-owl provides **continuous, audit-grade CIS Kubernetes compliance detection** with a strict **read-only, push-only** model. It complements enforcement systems; it does not replace them.

---

## Why elf-owl is required

Security programs need compliance evidence that is:

- **Continuous** (not only periodic scanner snapshots).
- **Low risk** (read-only operation, no mutation side effects).
- **Audit-friendly** (signed/encrypted evidence trail).
- **Runtime-aware** (kernel events correlated with workload identity).

elf-owl fills this gap by converting runtime + Kubernetes context into CIS control evaluations and immutable evidence payloads.

---

## Role in a layered security stack

- **Network layer:** segmentation and traffic controls.
- **Runtime layer:** exploit/threat controls, optional blocking.
- **Compliance layer (elf-owl):** detection + evidence generation for CIS controls.

In Kubernetes deployments, elf-owl runs as a **DaemonSet agent** per node to observe host runtime signals and enrich with pod/service-account/network-policy/RBAC context.

Outside Kubernetes, elf-owl can run in **no-K8s mode** for monitor-only telemetry (partial context, no pod metadata).

---

## What elf-owl does

- Detects CIS Kubernetes controls using event + metadata conditions.
- Correlates process/network/dns/file/capability events with workload context.
- Produces evidence batches with:
  - HMAC-SHA256 signatures
  - AES-256-GCM encryption
  - retry + backoff + gzip batching
- Pushes evidence to Owl API over outbound-only HTTPS/TLS.

---

## What elf-owl does NOT do

- No workload blocking, quarantine, or policy enforcement.
- No inbound command channel.
- No Kubernetes object mutation.
- No replacement for firewall/WAF/SIEM/scanner products.

These constraints are intentional to preserve safety and audit integrity.

---

## Boundaries and assumptions

- **Read-only by design**: enforcement belongs to other components.
- **Best signal quality in Kubernetes mode**: pod/RBAC/network-policy/audit fields come from Kubernetes context.
- **No-K8s mode is supported**: events still flow, but Kubernetes-derived fields are intentionally absent.
- **Configuration guardrail**: `kubernetes_metadata=false` with `kubernetes_only=true` is invalid and blocked at startup.

---

## Operational requirement summary

To run elf-owl effectively:

1. Ensure kernel/eBPF support on nodes.
2. Provide cluster identity and Owl API endpoint/token.
3. Use Kubernetes mode for full CIS context, or no-K8s mode for monitor-only runtime telemetry.
4. Validate with `/health`, `/metrics`, and script-driven smoke/event matrix tests.
