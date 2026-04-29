# elf-owl: Minimal Kubernetes Compliance Observer

**A read-only, push-only compliance agent for CIS Kubernetes v1.8 detection and monitoring**

> **Status:** Active development
> **Current Version:** 0.1.0
> **Last Updated:** April 29, 2026

---

## Overview

elf-owl detects CIS Kubernetes control violations from runtime activity and Kubernetes metadata using:

- **cilium/ebpf monitors** for process, network, DNS, file, capability, and TLS events.
- **JA3 fingerprinting** of outbound TLS ClientHellos via eBPF kernel capture (write/sendmsg/writev).
- **Outbound webhook pusher** — batches all enriched events and POSTs them as JSON arrays to an external ingest listener (e.g. ClickHouse ingest program).
- **Read-only design** with no enforcement or inbound control channel.
- **Push-only evidence flow** to Owl API.
- **Signed + encrypted evidence** with HMAC-SHA256 and AES-256-GCM.

It supports:

- **Kubernetes mode**: full K8s metadata enrichment (`kubernetes_metadata=true`, `kubernetes_only=true`).
- **No-K8s mode**: monitor-only runtime mode (`kubernetes_metadata=false`, `kubernetes_only=false`).

---

## Architecture

```text
cilium/ebpf Kernel Events (process / network / dns / file / capability / tls)
    -> TLS: JA3 fingerprint + SNI cert probe (async, 10-min cache)
    -> Enrichment (K8s pod context when enabled)
    -> Rule Engine (CIS controls)
    -> Evidence Signing + Encryption
    -> Buffering + Retry
    -> Owl API Push
    -> Outbound Webhook Pusher (batched JSON POST to external ingest listener)

External ClickHouse Ingest Program
    <- POST /events  [{type, timestamp, cluster_id, kubernetes, process|network|..., violations}]
    <- stores events in ClickHouse for analytics and alerting
```

**Design invariant:** read-only and push-only. elf-owl only emits data outward; it accepts no commands.

---

## Project Structure

```text
elf-owl/
├── cmd/elf-owl/                 # Agent entry point
├── pkg/
│   ├── agent/                   # Orchestrator + pipeline wiring
│   │   └── webhook.go           # Inbound webhook handler
│   ├── ebpf/                    # cilium/ebpf loaders + monitors
│   │   └── programs/tls.c       # TLS ClientHello eBPF capture (write/sendmsg/writev)
│   ├── ja3/                     # Shared JA3 parser (used by ebpf + enrichment)
│   ├── enrichment/              # Event context enrichment
│   ├── rules/                   # CIS rule engine + mappings
│   ├── evidence/                # Signing, encryption, buffering
│   ├── api/                     # Owl API push client
│   ├── kubernetes/              # K8s metadata client/cache
│   ├── metrics/                 # Prometheus metrics
│   └── logger/                  # Structured logging
├── config/
│   ├── elf-owl.yaml             # Default configuration
│   ├── elf-owl.tls-only.yaml    # TLS-only profile (all other monitors disabled)
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

### 1. Provision the VM (first time only)

```bash
scripts/setup-vm.sh --name elf-owl-dev --cpus 2 --memory 6G --disk 20G
```

### 2. Build eBPF programs

Compiles all C programs (process, network, dns, file, capability, tls) and pulls the `.o` bytecode back to the local repo:

```bash
scripts/build-ebpf-vm.sh --name elf-owl-dev --sync --pull
```

### 3. Start the agent

**Kubernetes mode:**

```bash
scripts/setup-k8s-vm.sh --name elf-owl-dev --kubeconfig /home/ubuntu/.kube/config
scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug \
  --kubeconfig /home/ubuntu/.kube/config
```

**No-K8s mode (monitor-only, fastest path for local dev):**

```bash
scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug --no-k8s
```

**With outbound webhook pusher enabled:**

```bash
# Start a listener in the VM first (see Testing the Webhook section below)
scripts/start-agent.sh --name elf-owl-dev --no-k8s --rebuild \
  --enable-webhook --webhook-url http://127.0.0.1:8888/events
# prints: Webhook pusher: pushing all enriched events to http://127.0.0.1:8888/events
```

### 4. Generate events

```bash
# Trigger process, file, network, dns, capability, and tls activity
scripts/generate-events.sh --name elf-owl-dev
```

### 5. Validate

```bash
scripts/check-state.sh   --name elf-owl-dev    # health + metrics + webhook push status
scripts/event-summary.sh --name elf-owl-dev    # event counts per type
scripts/check-event-values.sh --name elf-owl-dev --lines 5
```

### Full live integration test (one command)

```bash
# With K8s
scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild --sample-lines 5

# No-K8s + webhook push smoke test
scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild \
  --without-k8s --enable-webhook --sample-lines 5
```

### TLS-only validation profile

Use the isolated profile when testing the TLS path without perf pressure from other monitors:

```bash
cp config/elf-owl.tls-only.yaml config/elf-owl.yaml
go build -o elf-owl ./cmd/elf-owl
sudo OWL_K8S_IN_CLUSTER=false OWL_KUBERNETES_METADATA=false OWL_KUBERNETES_ONLY=false ./elf-owl
```

---

## Local Build (No VM)

```bash
go mod download
go build -mod=mod -o elf-owl ./cmd/elf-owl
```

See `SETUP_LINUX.md` for full host setup including eBPF kernel requirements.

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
kubectl apply -k deploy/kustomize/overlays/with-rules
```

---

## Runtime Endpoints

| Endpoint | Default | Purpose |
|---|---|---|
| `GET /health` | `:9091` | Liveness / readiness probe |
| `GET /metrics` | `:9090` | Prometheus scrape |

```bash
# Health
curl -sf http://127.0.0.1:9091/health

# Metrics
curl -sf http://127.0.0.1:9090/metrics | grep '^elf_owl_' | head
```

### Outbound Webhook Pusher

elf-owl can push all enriched events to an external HTTP ingest listener. Your listener receives batches of `WebhookEvent` JSON records:

```json
[
  {
    "type": "tls",
    "timestamp": "2026-04-29T12:00:00Z",
    "cluster_id": "prod-us-east-1",
    "node_name": "node-1",
    "kubernetes": { "pod_name": "...", "namespace": "...", ... },
    "tls": { "ja3": "...", "sni": "example.com", ... },
    "violations": [{ "control_id": "CIS_4.2.6", "severity": "HIGH", ... }]
  }
]
```

**Enable via environment (no YAML edit needed):**

```bash
export OWL_WEBHOOK_ENABLED=true
export OWL_WEBHOOK_TARGET_URL=http://my-ingest-host:8888/events
```

**Payload field availability by event type:**

| `type` | Populated context fields |
|---|---|
| `process` | `process`, `kubernetes`, `container` |
| `network` | `network`, `kubernetes`, `container` |
| `dns` | `dns`, `kubernetes`, `container` |
| `file` | `file`, `kubernetes`, `container` |
| `capability` | `capability`, `kubernetes`, `container` |
| `tls` | `tls`, `kubernetes`, `container` |

All types include `violations` when CIS rules matched.

---

## Configuration Reference

Default file: `config/elf-owl.yaml`

Search order at runtime:

1. `./config/elf-owl.yaml`
2. `/etc/elf-owl/elf-owl.yaml`
3. `$HOME/.config/elf-owl/elf-owl.yaml`

### Key Environment Overrides

| Variable | Purpose |
|---|---|
| `OWL_CLUSTER_ID` | Cluster identifier |
| `OWL_NODE_NAME` | Node name (falls back to `$HOSTNAME`) |
| `OWL_API_ENDPOINT` | Owl SaaS push target |
| `OWL_LOG_LEVEL` | `debug` / `info` / `warn` / `error` |
| `OWL_K8S_IN_CLUSTER` | `false` for out-of-cluster kubeconfig mode |
| `OWL_KUBERNETES_ONLY` | Discard events with no pod context (default `true`) |
| `OWL_KUBERNETES_METADATA` | Disable K8s client entirely (default `true`) |
| `OWL_WEBHOOK_ENABLED` | Enable outbound webhook pusher (default `false`) |
| `OWL_WEBHOOK_TARGET_URL` | Target URL for outbound event push (required when enabled) |
| `ELF_OWL_SIGNING_KEY` | HMAC-SHA256 signing key |
| `ELF_OWL_ENCRYPTION_KEY` | AES-256-GCM encryption key |
| `KUBECONFIG` | Path to kubeconfig (out-of-cluster mode) |
| `AGENT_NAMESPACE` | Pod lookup fast-path namespace (Helm injects from `metadata.namespace`) |

**No-K8s runtime:**

```bash
export OWL_K8S_IN_CLUSTER=false
export OWL_KUBERNETES_METADATA=false
export OWL_KUBERNETES_ONLY=false
```

**Enable webhook without editing YAML:**

```bash
export OWL_WEBHOOK_ENABLED=true
export OWL_WEBHOOK_TARGET_URL=http://ingest-host:8888/events
```

### Webhook config block (`config/elf-owl.yaml`)

```yaml
agent:
  webhook:
    enabled: false
    target_url: ""                # Required when enabled
    batch_size: 100               # Max events per POST body
    flush_interval: 5s            # Flush timer
    timeout: 10s                  # HTTP client timeout per POST
    # headers:
    #   Authorization: "Bearer <token>"
```

---

## Scripts Reference

All scripts live in `scripts/` and target a Multipass VM named `elf-owl-dev` by default. Pass `--name <vm>` to override.

| Script | Purpose |
|---|---|
| `setup-vm.sh` | Provision Multipass VM with Go + eBPF toolchain |
| `setup-k8s-vm.sh` | Install k3s in VM and extract kubeconfig |
| `sync-vm-src.sh` | Archive + transfer local source into VM |
| `build-ebpf-vm.sh` | Compile eBPF C programs in VM; `--pull` copies `.o` files back |
| `start-agent.sh` | Build (optional) + start agent; supports `--no-k8s`, `--enable-webhook`, `--webhook-url` |
| `stop-agent.sh` | Stop running agent process |
| `generate-events.sh` | Trigger process/file/network/dns/capability/tls activity |
| `check-state.sh` | Health + metrics + outbound webhook push status |
| `check-logs.sh` | Filter agent logs by category |
| `event-summary.sh` | Count events per type from log |
| `check-event-values.sh` | Sample log lines per event type |
| `test-events.sh` | Unit + integration test matrix in VM (includes `pkg/ja3`, TLS, webhook) |
| `test-live-events.sh` | Full live flow: K8s setup → agent start → events → assertions |
| `test-ebpf-kernel.sh` | Root kernel eBPF integration tests (requires VM root) |
| `vm-exec.sh` | Run arbitrary commands inside VM |
| `generate-vmlinux.sh` | Regenerate `vmlinux.h` from kernel BTF via bpftool |

### Common flag combinations

```bash
# Rebuild eBPF and agent, start with webhook
scripts/build-ebpf-vm.sh --sync --pull
scripts/start-agent.sh --sync --rebuild --no-k8s --enable-webhook

# Generate all event types including a webhook POST
scripts/generate-events.sh --webhook --tls-host example.com

# Run full VM test matrix
scripts/test-events.sh --sync --kernel

# Full no-k8s live test with webhook smoke
scripts/test-live-events.sh --sync --rebuild --without-k8s --enable-webhook
```

---

## Testing

```bash
# Full repo
GOCACHE=/tmp/elf-owl-gocache go test ./...

# Focused packages
go test ./pkg/ja3 ./pkg/rules ./pkg/api ./pkg/evidence

# VM event path + unit matrix
scripts/test-events.sh --name elf-owl-dev --sync

# VM matrix + kernel eBPF integration suite
scripts/test-events.sh --name elf-owl-dev --sync --kernel
```

---

## Troubleshooting

### Agent exits early in VM

Use one of:

```bash
scripts/start-agent.sh ... --kubeconfig /home/ubuntu/.kube/config
scripts/start-agent.sh ... --no-k8s
```

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

### Webhook pusher not sending events

- Confirm `OWL_WEBHOOK_ENABLED=true` and `OWL_WEBHOOK_TARGET_URL` is set (non-empty).
- A missing `target_url` is caught at startup with: `webhook.enabled=true requires webhook.target_url to be set`.
- Check the agent log for `webhook pusher started` at startup, and `webhook batch pushed` at debug level.
- If you see `webhook push failed`, the listener is unreachable — verify the target host/port is up.

### Webhook batches not arriving at listener

- Verify the listener is bound before the agent starts (agent won't buffer across listener restarts).
- Default `flush_interval` is 5 s — wait at least one interval after generating events.
- Use `--log-level debug` and grep for `webhook batch pushed` in the agent log.
- Confirm the listener returns HTTP 2xx; a 4xx/5xx causes a warning log but events are dropped.

### TLS events not appearing

- Confirm the TLS monitor is enabled (`ebpf.tls.enabled: true` in config, which is the default).
- Use `--log-level debug` and check for `tls event read` or `tls ja3 parsed` log lines.
- TLS capture requires outbound HTTPS traffic. Run `scripts/generate-events.sh` which calls `curl -sk https://example.com`.
- If `tls.o` is missing, rebuild: `scripts/build-ebpf-vm.sh --sync --pull`.

---

## License

[Elastic License 2.0](LICENSE)

## Support

Open a GitHub issue with the script command used, relevant logs, and `/health` output.
