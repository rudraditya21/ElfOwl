# CODEX Review Status (Against `REVIEW.md`)

**Date:** March 29, 2026  
**Compared Source:** `REVIEW.md`  
**Branch Snapshot:** `rudraditya/fixes` (current workspace)

This document tracks the implementation status of each issue listed in `REVIEW.md`.

Status meanings:
- **Open**: issue still present.
- **Partial**: remediation landed, but risk remains.
- **Closed**: issue no longer present.
- **Informational**: architecture/by-design observation, not a code defect.

---

## Critical Weaknesses

| ID | Status | Current State | Evidence |
|---|---|---|---|
| C1 | **Closed** | Build no longer hard-fails when eBPF `.o` files are absent; `make ebpf` path and embed fallback are in place. | `pkg/ebpf/bytecode_embed.go`, `Makefile` |
| C2 | **Closed** | `RBACEnforced` now derives from RBAC API-group discovery (`rbac.authorization.k8s.io`) instead of `rbac_level >= 0`. | `pkg/kubernetes/client.go`, `pkg/enrichment/enricher.go`, `pkg/agent/compliance_watcher.go` |
| C3 | **Closed** | Multi-container metadata extraction is container-specific (`GetPodMetadataForContainer`) and no longer defaults to `containers[0]`. | `pkg/kubernetes/client.go`, `pkg/kubernetes/client_mapping_test.go` |
| C4 | **Closed** | RBAC level now maps from permission counts (0 / 1-10 / 11-100 / 100+) and no longer uses binding-count/admin short-circuit heuristics. | `pkg/kubernetes/client.go`, `pkg/kubernetes/rbac_logic_test.go` |

---

## High Severity Weaknesses

| ID | Status | Current State | Evidence |
|---|---|---|---|
| H1 | **Closed** | CIS 4.3.1 now enforces a registry allowlist via `not_in` (rather than `!= docker.io`). | `pkg/rules/cis_mappings.go`, `pkg/rules/compliance_field_behavior_test.go` |
| H2 | **Closed** | CIS 4.9.1 enforces runtime allowlist semantics via `not_in` approved runtimes (violates on non-approved/unknown runtime). | `pkg/rules/cis_mappings.go`, `pkg/rules/compliance_field_behavior_test.go` |
| H3 | **Closed** | Seccomp/AppArmor duplicate inflation was removed by splitting semantics: runtime checks catch explicit `unconfined`, pod-spec checks catch missing profile (`""`). | `pkg/rules/cis_mappings.go`, `pkg/rules/compliance_field_behavior_test.go` |
| H4 | **Closed** | `RBACPolicyDefined`, `RolePermissionCount`, and `ServiceAccountPermissions` now come from distinct calculations. | `pkg/kubernetes/client.go`, `pkg/enrichment/enricher.go`, `pkg/agent/compliance_watcher.go` |
| H5 | **Closed** | Rule equality now uses type-normalized comparison; YAML numeric type mismatch risk is mitigated. | `pkg/rules/engine.go`, `pkg/rules/engine_test.go` |
| H6 | **Closed** | Enrichment path now enforces bounded K8s API call deadlines (`2s`) with context propagation. | `pkg/enrichment/enricher.go`, `pkg/enrichment/enricher_test.go` |
| H7 | **Closed** | Metadata cache now has active periodic cleanup of expired pod/node/container/cgroup entries. | `pkg/kubernetes/cache.go`, `pkg/kubernetes/cache_test.go` |

---

## Medium Severity Weaknesses

| ID | Status | Current State | Evidence |
|---|---|---|---|
| M1 | **Closed** | Projected service-account token TTL is now populated (non-zero signal on 1.22+ clusters) and propagated to compliance fields. | `pkg/kubernetes/pod_fields.go`, `pkg/kubernetes/client.go`, `pkg/enrichment/enricher.go`, `pkg/agent/compliance_watcher.go` |
| M2 | **Closed** | ClusterRoleBinding subject matching now handles empty namespace subjects for service accounts. | `pkg/kubernetes/client.go`, `pkg/kubernetes/rbac_logic_test.go` |
| M3 | **Closed** | CIS 4.9.2 threshold remains `isolation_level < 1` with explicit ANCHOR rationale documenting false-positive reduction intent. | `pkg/rules/cis_mappings.go`, `pkg/rules/compliance_field_behavior_test.go` |
| M4 | **Closed** | Stale “stub controls / week-2 TODO” comments removed and wording synced to current implementation state. | `pkg/rules/engine.go`, `pkg/rules/cis_mappings.go`, `pkg/kubernetes/client.go` |
| M5 | **Closed** | TLS config build failures are now startup-fatal (no warn-and-silent-fallback behavior). | `pkg/agent/agent.go`, `pkg/api/client_test.go` |
| M6 | **Closed** | `AGENT_NAMESPACE` is now injected in Helm DaemonSet and documented in config/readme. | `deploy/helm/templates/daemonset.yaml`, `config/elf-owl.yaml`, `README.md` |
| M7 | **Closed** | CIS_5.1.1 is no longer dead: `rbac_enforced` is no longer permanently true for `pod_spec_check` paths. | `pkg/enrichment/enricher.go`, `pkg/agent/compliance_watcher.go`, `pkg/kubernetes/client.go` |

---

## Low Severity Weaknesses

| ID | Status | Current State | Evidence |
|---|---|---|---|
| L1 | **Closed** | `regex` operator is implemented in evaluator switch and covered by tests. | `pkg/rules/engine.go`, `pkg/rules/engine_test.go` |
| L2 | **Closed** | Wildcard RBAC verbs are now weighted (not counted as a single permission). | `pkg/kubernetes/client.go`, `pkg/kubernetes/rbac_logic_test.go` |
| L3 | **Closed** | Container lookup now prefers node-scoped listing and avoids redundant miss paths; API calls are limiter-gated. | `pkg/kubernetes/client.go`, `pkg/kubernetes/client_rate_limit_test.go` |
| L4 | **Closed** | Monitor placeholder initialization was removed; monitor lifecycle now starts only after successful program load. | `pkg/agent/agent.go`, `pkg/agent/agent_init_test.go` |
| L5 | **Closed** | Managed control-plane audit detection no longer hard-returns false when kube-apiserver pods are invisible. | `pkg/kubernetes/client.go`, `pkg/kubernetes/audit_helpers_test.go` |
| L6 | **Closed** | Static hardcoded fallback signing/encryption keys were removed; ephemeral generated keys are used when secrets are absent. | `pkg/agent/agent.go`, `pkg/agent/agent_init_test.go` |

---

## Architecture-Level Gaps

| ID | Status | Current State | Evidence |
|---|---|---|---|
| A1 | **Closed** | K8s client now has explicit API rate limiting (`OWL_K8S_API_RATE_LIMIT`, `OWL_K8S_API_BURST`). | `pkg/kubernetes/client.go`, `pkg/kubernetes/client_rate_limit_test.go` |
| A2 | **Closed** | Container mapping cache path was consolidated to Kubernetes cache as source-of-truth to avoid dual-cache drift. | `pkg/enrichment/enricher.go`, `pkg/kubernetes/cache.go` |
| A3 | **Closed** | Live rule reload added via periodic reload + signature detection + atomic engine swap. | `pkg/agent/agent.go`, `pkg/agent/agent_init_test.go` |
| A4 | **Informational** | CIS benchmark coverage gap for control-plane/node/etcd checks remains structural for runtime eBPF scope. | `pkg/rules/cis_mappings.go`, docs |
| A5 | **Informational** | Runtime-only detection remains by design; no admission-time blocking component in this agent. | system architecture |

---

## Snapshot Summary

- **Closed:** 27
- **Partial:** 0
- **Open:** 0
- **Informational:** 2 (`A4`, `A5`)

## Post-Fix Reconciliation (User Review vs Current Code)

This section reconciles the external post-fix review (dated March 29, 2026) with the current branch state.

### User-reported residual bugs

| External Bug | Reconciled Status | Codex Assessment | Evidence / Fix Commit |
|---|---|---|---|
| Bug 1: CIS_4.9.1 runtime rule inverted | **Closed (Clarified)** | `not_in [containerd, cri-o, crio]` is correct allowlist violation logic (fires on non-approved runtime). Clarifying ANCHOR/test added. | `pkg/rules/cis_mappings.go`, `pkg/rules/compliance_field_behavior_test.go`, `ff1cedb` |
| Bug 2: CIS_4.2.7/4.7.1 and 4.2.8/4.7.2 duplicate behavior | **Closed** | Rules were split to avoid duplicate signal inflation across runtime vs pod-spec paths: runtime=`unconfined`, pod-spec=`missing profile`. | `pkg/rules/cis_mappings.go`, `pkg/rules/compliance_field_behavior_test.go`, `43b70ca` |
| Bug 3: CIS_4.9.2 threshold change undocumented | **Closed** | Rule remained `< 1`; explicit rationale comment (ANCHOR) added to document intent and tradeoff. | `pkg/rules/cis_mappings.go`, `72fcc73` |
| Bug 4: `role_permission_count` semantic mismatch | **Closed** | `RolePermissionCount` now uses `MaxRolePermissionCount` (max permissions in a bound role), not bound-role count. | `pkg/kubernetes/client.go`, `pkg/enrichment/enricher.go`, `pkg/agent/compliance_watcher.go`, `pkg/kubernetes/rbac_logic_test.go`, `c12746e` |

### External "still-open" list reconciliation

Items reported open in the external review are now closed in this branch:
- `M1`: projected token lifetime populated (`bbee914`)
- `M5`: TLS build failure is startup-fatal (`f886b13`)
- `M6`: `AGENT_NAMESPACE` Helm/docs wired (`b118a42`)
- `L3`: container lookup fallback/API pressure optimized (`97d84d1`)
- `L5`: managed-cluster audit detection returns unknown-safe behavior (`e246c3c`)
- `L6`: hardcoded fallback keys removed (`f886b13`)
- `A1`: K8s API rate limiting added (`97d84d1`)
- `A3`: live rule reload implemented (`711bd5a`)

## Remaining Implementation Work

1. No unresolved code defects remain from `REVIEW.md`.
2. `A4` and `A5` remain design-scope informational items (not runtime bugs).
