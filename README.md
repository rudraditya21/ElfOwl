# elf-owl: Minimal Kubernetes Compliance Observer

**A read-only, push-only compliance agent for CIS Kubernetes v1.8 detection and monitoring**

> **Status:** Active development
> **Current Version:** 0.1.0
> **Last Updated:** March 29, 2026

---

## Overview

elf-owl detects CIS Kubernetes control violations from runtime activity and Kubernetes metadata using:

- **cilium/ebpf monitors** for process, network, DNS, file, and capability events.
- **Read-only design** with no enforcement or inbound control channel.
- **Push-only evidence flow** to Owl API.
- **Signed + encrypted evidence** with HMAC-SHA256 and AES-256-GCM.

It supports:

- **Kubernetes mode**: full K8s metadata enrichment (`kubernetes_metadata=true`, `kubernetes_only=true`).
- **No-K8s mode**: monitor-only runtime mode (`kubernetes_metadata=false`, `kubernetes_only=false`).

---

## Architecture

```text
cilium/ebpf Kernel Events
    -> Enrichment (K8s context when enabled)
    -> Rule Engine (CIS controls)
    -> Evidence Signing + Encryption
    -> Buffering + Retry
    -> Owl API Push
```

**Design invariant:** read-only and push-only.

---

## Project Structure

```text
elf-owl/
├── cmd/elf-owl/                 # Agent entry point
├── pkg/
│   ├── agent/                   # Orchestrator + pipeline wiring
│   ├── ebpf/                    # cilium/ebpf loaders + monitors
│   ├── enrichment/              # Event context enrichment
│   ├── rules/                   # CIS rule engine + mappings
│   ├── evidence/                # Signing, encryption, buffering
│   ├── api/                     # Owl API push client
│   ├── kubernetes/              # K8s metadata client/cache
│   ├── metrics/                 # Prometheus metrics
│   └── logger/                  # Structured logging
├── config/
│   ├── elf-owl.yaml             # Default configuration
│   └── rules/cis-controls.yaml  # CIS control definitions
├── deploy/
│   ├── helm/                    # Helm chart
│   └── kustomize/               # Kustomize base + overlays
├── scripts/                     # Multipass-based setup/test helpers
└── docs/                        # Installation/usage/reference docs
```

---

## Quick Start (VM + Multipass)

Recommended for reproducible local validation.

### Prerequisites

- Multipass installed on host.
- Linux guest support (Ubuntu image via Multipass).

### Setup + Build + Start (K8s mode)

```bash
scripts/setup-vm.sh --name elf-owl-dev --cpus 2 --memory 6G --disk 20G
scripts/setup-k8s-vm.sh --name elf-owl-dev --kubeconfig /home/ubuntu/.kube/config
scripts/build-ebpf-vm.sh --name elf-owl-dev --sync --pull
scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug --kubeconfig /home/ubuntu/.kube/config
```

### No-K8s mode

```bash
scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug --no-k8s
```

### Validate

```bash
scripts/check-state.sh --name elf-owl-dev
scripts/test-events.sh --name elf-owl-dev --sync
scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild --sample-lines 5
scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild --sample-lines 5 --without-k8s
```

---

## Local Build (No VM)

```bash
go mod download
go build -mod=mod -o elf-owl ./cmd/elf-owl
```

See `SETUP_LINUX.md` for full host setup.

---

## Deployment

### Helm (local chart)

```bash
kubectl create namespace elf-owl-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic elf-owl-api-token \
  --from-literal=api-token=YOUR_API_TOKEN \
  -n elf-owl-system \
  --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install elf-owl ./deploy/helm \
  --namespace elf-owl-system \
  --set clusterID=prod-us-east-1 \
  --set owl.endpoint=https://owl-saas.example.com \
  --set owl.apiTokenSecret=elf-owl-api-token
```

Optional rules ConfigMap source:

```bash
helm upgrade --install elf-owl ./deploy/helm \
  --namespace elf-owl-system \
  --set rules.configMap.enabled=true
```

### Kustomize

```bash
kubectl apply -k deploy/kustomize/overlays/production
# Optional starter rules overlay
kubectl apply -k deploy/kustomize/overlays/with-rules
```

---

## Runtime Endpoints

- Health: `http://127.0.0.1:9091/health`
- Metrics: `http://127.0.0.1:9090/metrics`

```bash
curl -sf http://127.0.0.1:9091/health
curl -sf http://127.0.0.1:9090/metrics | grep '^elf_owl_' | head
```

---

## Configuration Reference

Default file: `config/elf-owl.yaml`

Search order at runtime:

1. `./config/elf-owl.yaml`
2. `/etc/elf-owl/elf-owl.yaml`
3. `$HOME/.config/elf-owl/elf-owl.yaml`

### Key Environment Overrides

- `OWL_CLUSTER_ID`
- `OWL_NODE_NAME`
- `OWL_API_ENDPOINT`
- `OWL_JWT_TOKEN`
- `OWL_LOG_LEVEL`
- `OWL_K8S_IN_CLUSTER`
- `OWL_KUBERNETES_ONLY`
- `OWL_KUBERNETES_METADATA`
- `AGENT_NAMESPACE` (pod lookup fast path namespace; Helm injects this from `metadata.namespace`)
- `ELF_OWL_SIGNING_KEY`
- `ELF_OWL_ENCRYPTION_KEY`
- `KUBECONFIG` (out-of-cluster Kubernetes mode)

No-K8s runtime requires:

```bash
export OWL_K8S_IN_CLUSTER=false
export OWL_KUBERNETES_METADATA=false
export OWL_KUBERNETES_ONLY=false
```

---

## Testing

```bash
# Full repo
GOCACHE=/tmp/elf-owl-gocache go test ./...

# Focused packages
go test ./pkg/rules ./pkg/api ./pkg/evidence

# VM path/event matrix (+ optional kernel suite)
scripts/test-events.sh --name elf-owl-dev --sync
scripts/test-events.sh --name elf-owl-dev --sync --kernel
```

---

## Troubleshooting

### Agent exits early in VM

Use one of:

- `scripts/start-agent.sh ... --kubeconfig /home/ubuntu/.kube/config`
- `scripts/start-agent.sh ... --no-k8s`

Then inspect logs:

```bash
scripts/check-logs.sh --name elf-owl-dev --type startup --lines 120
```

### Missing metadata in Kubernetes mode

- Verify kubeconfig path exists in VM.
- Verify `OWL_K8S_IN_CLUSTER=false` for out-of-cluster runs.
- Verify RBAC and K8s API reachability.

### No events in no-K8s mode

- Ensure `OWL_KUBERNETES_METADATA=false` and `OWL_KUBERNETES_ONLY=false`.
- Confirm startup log contains `running without Kubernetes client`.

---

## License

[Elastic License 2.0](LICENSE)

## Support

Open a GitHub issue with script command used, relevant logs, and `/health` output.
