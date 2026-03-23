# elf-owl Requirement and Role in Kubernetes

**Purpose:** Define why elf-owl is required, what role it plays in a Kubernetes security stack, and what it explicitly does not do.

## Elf-owl is required to deliver **continuous, audit-grade CIS compliance** in Kubernetes. It is the **compliance observer** in a layered security architecture, designed to be safe, read-only, and evidence-focused. It complements, but does not replace, runtime and network enforcement systems.

---

## Why elf-owl is required

Kubernetes security programs need **evidence-grade compliance visibility** that is:

- **Read-only and safe** for audits (no enforcement side effects).
- **Continuous** rather than point-in-time scans.
- **Immutable** with signed and encrypted evidence for audit trails.
- **Kubernetes-native** with pod, namespace, service account, and policy context.

elf-owl fills this requirement by focusing on **CIS Kubernetes v1.8 compliance detection** and **evidence production**. It complements runtime security and network controls rather than duplicating them.

---

## Role in a Kubernetes security stack

elf-owl is the **compliance and audit layer** in a multi-layer security model:

- **Network layer:** perimeter and east-west controls (e.g., firewall / network policy enforcement).
- **Runtime layer:** threat detection and enforcement (e.g., process, file, and capability monitoring with optional blocking).
- **Compliance layer (elf-owl):** continuous CIS control detection with signed/encrypted evidence.

In the unified CloudArmour model, elf-owl acts as a **single-replica, read-only controller** that:

- Watches Kubernetes objects relevant to CIS controls (pods, service accounts, RBAC, network policies).
- Correlates runtime eBPF events with Kubernetes metadata.
- Emits compliance violations to the control plane for reporting and audit storage.

---

## What elf-owl does

- **CIS Kubernetes v1.8 compliance detection** (48 automated controls + 9 manual references).
- **Read-only monitoring** of Kubernetes configuration and runtime signals.
- **Evidence generation** with HMAC-SHA256 signatures and AES-256-GCM encryption.
- **Push-only telemetry** to a control plane or SaaS endpoint.
- **Kubernetes metadata enrichment** (pod, namespace, service account, labels, policies).

---

## Known limitations

ANCHOR: Known limitations - Compliance fields not populated yet - Mar 22, 2026

Some CIS controls rely on fields that are not yet populated in the current pipeline. These may
result in **unknown == violation** behavior until those fields are implemented. Examples include:

- `container.image_scan_status`, `container.image_signed`, `container.image_registry_auth`
- `container.volume_type`, `container.storage_request`, `container.kernel_hardening`

This does **not** affect the read-only model, but it does affect the accuracy of those specific
controls until the underlying signals are implemented.

---

## What elf-owl does NOT do

elf-owl is intentionally limited to avoid enforcement risk and to preserve audit integrity.

It does **not**:

- Enforce policies or block workloads (no pod killing, no syscall blocking).
- Act as a firewall or NetworkPolicy controller.
- Provide cluster edge protection or DDoS mitigation.
- Serve inbound command channels or accept remote instructions.
- Replace runtime threat detection products.
- Replace SIEMs, log pipelines, or cluster configuration scanners.

---

## Boundaries and assumptions

- **Read-only by design:** any enforcement is delegated to other products.
- **Kubernetes context required:** compliance evaluation depends on pod and policy metadata.
- **Audit-first architecture:** evidence is signed, encrypted, and pushed outward.
- **Separation of concerns:** elf-owl focuses on compliance signals, not remediation.

---

