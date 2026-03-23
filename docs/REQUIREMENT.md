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

ANCHOR: Known limitations - Compliance fields depend on pod signals - Mar 22, 2026

Some CIS controls rely on fields that are populated **only when specific pod signals exist**.
If those signals are absent, the fields default to empty/false and may be interpreted as a
violation, so treat these as **signal missing** rather than definitive failures in such cases.

Signal sources include:
- Pod annotations/labels `image-scan-status` and `image-signed` for image scanning and signature status.
- `imagePullSecrets` on the pod or its ServiceAccount for registry authentication.
- Container volume mounts to determine `container.volume_type` (e.g., hostPath/emptyDir/local).
- Pod `securityContext.sysctls` (kernel.*) for kernel hardening.
- Ephemeral storage requests for `container.storage_request`.

This does **not** affect the read-only model, but it does affect the accuracy of those specific
controls until the underlying signals are consistently provided.

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
