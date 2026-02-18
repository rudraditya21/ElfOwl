# elf-owl: Minimal Kubernetes Compliance Observer

**A read-only, push-only compliance agent for CIS Kubernetes v1.8 detection and monitoring**

> **Status:** 🚀 Bootstrap Complete - Week 2-6 Implementation In Progress
> **Current Version:** 0.1.0 (Development)
> **Date:** December 26, 2025

---

## Overview

elf-owl is a minimal compliance observer agent that detects CIS Kubernetes v1.8 violations using:

- **cilium/ebpf Integration**: Kernel-native eBPF monitoring via the production-grade cilium/ebpf library
- **Read-Only Design**: Zero enforcement capability (only detection)
- **Push-Only Architecture**: One-way outbound to Owl SaaS (no inbound commands)
- **Signed + Encrypted Evidence**: HMAC-SHA256 signing + AES-256-GCM encryption
- **Minimal Footprint**: ~1200 LOC core agent code

### Key Features

✅ **eBPF Runtime Security Monitoring**
- Process execution tracking
- Network connection monitoring
- DNS query tracking
- File access auditing
- Linux capability usage detection

✅ **CIS Kubernetes Compliance**
- Detects 48 automated violations
- Supports 9 manual review controls
- Maps to remediation guides

✅ **Kubernetes Integration**
- In-cluster pod metadata enrichment
- Service account context
- Container image tracking
- Owner reference tracking

✅ **Evidence Protection**
- HMAC-SHA256 signing for integrity
- AES-256-GCM encryption for confidentiality
- Batch compression for efficiency

✅ **Cloud-Native Deployment**
- Kubernetes DaemonSet
- Helm charts + Kustomize overlays
- RBAC (read-only access)

---

## Architecture

```
cilium/ebpf Kernel Events
    ↓
Process/Network/DNS/File/Capability Monitors (cilium/ebpf)
    ↓
Event Enrichment (K8s metadata injection)
    ↓
Rule Engine (CIS control matching)
    ↓
Evidence Processing (sign + encrypt)
    ↓
Buffering & Batching
    ↓
Owl SaaS Push API (TLS, one-way)
```

**Design Invariant:** This agent is **READ-ONLY** and **PUSH-ONLY**
- No enforcement capability
- No inbound command channels
- No policy changes to cluster
- Safe for customer environments

---

## Project Structure

```
elf-owl/
├── cmd/elf-owl/                 # Agent entry point (100 LOC)
├── pkg/
│   ├── agent/                   # Core orchestrator (450 LOC)
│   ├── enrichment/              # Event enrichment pipeline (530 LOC)
│   ├── rules/                   # Rule engine & CIS mappings (480 LOC)
│   ├── evidence/                # Signing, encryption, buffering (240 LOC)
│   ├── api/                     # Owl SaaS client (API push)
│   ├── kubernetes/              # K8s metadata client (260 LOC)
│   ├── metrics/                 # Prometheus metrics
│   └── logger/                  # Structured logging
├── config/
│   ├── elf-owl.yaml             # Default configuration
│   └── cis-rules.yaml           # CIS control definitions (TBD)
├── deploy/
│   ├── helm/                    # Helm chart for K8s deployment
│   └── kustomize/               # Kustomize overlays
├── test/                        # Unit, integration, E2E tests
├── docs/                        # Architecture, deployment guides
└── go.mod                       # cilium/ebpf + Go module dependencies
```

**Total Implementation:** ~1200 LOC core code (excluding tests, docs, config)

---

## Implementation Timeline

### ✅ Week 1: Bootstrap (COMPLETE)
- [x] Project structure initialized
- [x] go.mod with cilium/ebpf dependency
- [x] Configuration schema (config.go)
- [x] Logger setup (logger.go)
- [x] Agent orchestrator skeleton (agent.go)
- [x] Evidence components (signer, cipher, buffer)
- [x] Kubernetes client stub (client.go, cache.go)
- [x] API client stub (api/client.go)
- [x] Enrichment types (enrichment/types.go)
- [x] Rule engine skeleton (rules/engine.go)

### ⏳ Week 2: Event Processing Pipeline
- [ ] Implement enrichment pipeline
  - [ ] Container ID extraction from cgroup
  - [ ] K8s pod metadata injection
  - [ ] Container runtime context
  - [ ] Owner reference resolution
- [ ] Implement rule engine
  - [ ] Condition evaluation logic
  - [ ] Add 48 automated CIS controls
  - [ ] Rule matching against events
- [ ] Create CIS control mappings (cis_mappings.go)
- [ ] Add rule loader (loader.go)

### ⏳ Week 3: Evidence & API
- [ ] Implement HMAC signing (complete)
- [ ] Implement AES encryption (complete)
- [ ] Implement API client
  - [ ] Event serialization
  - [ ] Batch formatting
  - [ ] gzip compression
  - [ ] TLS/JWT authentication
  - [ ] Retry logic with backoff
- [ ] Implement buffer flush logic

### ⏳ Week 4: Kubernetes Integration
- [ ] Implement K8s API client
  - [ ] Pod metadata queries
  - [ ] Node metadata queries
  - [ ] Owner reference resolution
- [ ] Implement metadata cache
  - [ ] TTL-based expiry
  - [ ] Container ID → Pod mapping
- [ ] Create Helm chart
  - [ ] DaemonSet definition
  - [ ] ConfigMap for rules
  - [ ] Secret for credentials
- [ ] Create RBAC definitions
  - [ ] ServiceAccount
  - [ ] ClusterRole (read-only)
  - [ ] ClusterRoleBinding

### ⏳ Week 5: Testing & Polish
- [ ] Unit tests (~620 LOC)
  - [ ] Rule matching tests
  - [ ] Enrichment tests
  - [ ] Evidence signing/encryption tests
  - [ ] API client tests
- [ ] Integration tests (~350 LOC)
  - [ ] Full event pipeline
  - [ ] K8s metadata injection
  - [ ] Mock cilium/ebpf monitor integration
- [ ] E2E tests (~150 LOC)
  - [ ] Deploy to test cluster
  - [ ] Generate violations
  - [ ] Verify event capture
- [ ] Add health check endpoints
- [ ] Add Prometheus metrics

### ⏳ Week 6: Documentation
- [ ] Architecture documentation
- [ ] CIS control reference
- [ ] Deployment guide
- [ ] Troubleshooting guide
- [ ] Configuration reference
- [ ] Contributing guide

---

## Quick Start

### Prerequisites

- Go 1.23+
- Kubernetes 1.24+ cluster (for deployment)
- cilium/ebpf library (auto-imported via go.mod)

### Build

```bash
cd elf-owl
go mod download
go build -o elf-owl cmd/elf-owl/main.go
```

### Configuration

Create `config/elf-owl.yaml` or use defaults in `pkg/agent/config.go`

```yaml
agent:
  cluster_id: "prod-us-east-1"
  node_name: "worker-01"
  owl_api:
    endpoint: "https://owl-saas.example.com"
```

### Environment Variables

```bash
export OWL_CLUSTER_ID="prod-us-east-1"
export OWL_NODE_NAME="worker-01"
export OWL_API_ENDPOINT="https://owl-saas.example.com"
export OWL_JWT_TOKEN="your-jwt-token"
export OWL_LOG_LEVEL="info"
```

### Run

```bash
./elf-owl
```

---

## Deployment

### Kubernetes DaemonSet (Helm)

```bash
helm install elf-owl ./deploy/helm \
  --namespace elf-owl-system \
  --create-namespace \
  --set clusterID=prod-us-east-1 \
  --set owlAPIEndpoint=https://owl-saas.example.com
```

### Kustomize

```bash
kubectl apply -k deploy/kustomize/overlays/production/
```

---

## API Reference

### Health Check

```bash
curl http://localhost:9091/health
```

Response:
```json
{
  "agent_version": "0.1.0",
  "uptime": "1h23m45s",
  "status": "healthy",
  "events_processed": 1523,
  "violations_found": 42,
  "monitors": {
    "process": true,
    "network": true,
    "dns": true,
    "file": true,
    "capability": true
  }
}
```

### Metrics

```bash
curl http://localhost:9090/metrics
```

Prometheus metrics:
- `elf_owl_events_processed_total`: Total events processed
- `elf_owl_violations_found_total`: Total CIS violations detected
- `elf_owl_push_success_total`: Successful push operations
- `elf_owl_push_failure_total`: Failed push operations
- `elf_owl_push_latency_seconds`: Push operation latency

---

## Configuration Reference

See `config/elf-owl.yaml` for all configuration options.

**Key Settings:**

| Setting | Default | Purpose |
|---------|---------|---------|
| `cluster_id` | default | Cluster identifier |
| `ebpf.process.enabled` | true | Process monitoring |
| `ebpf.network.enabled` | true | Network monitoring |
| `kubernetes.in_cluster` | true | K8s API access mode |
| `owl_api.endpoint` | - | Owl SaaS endpoint |
| `owl_api.push.batch_size` | 100 | Events per batch |
| `owl_api.push.batch_timeout` | 30s | Max batch wait time |

---

## Development

### Testing

```bash
# Unit tests
go test ./pkg/...

# Integration tests
go test ./test/integration/...

# E2E tests (requires cluster)
go test ./test/e2e/...
```

### Code Structure

- **Core Agent**: `pkg/agent/agent.go` (orchestrates cilium/ebpf monitors)
- **eBPF Integration**: `github.com/cilium/ebpf` via `pkg/ebpf/` monitors
- **Event Pipeline**: eBPF → enrichment → rules → evidence → push
- **No Wrapper Layer**: Clean dependency injection

### Adding New Rules

Edit `pkg/rules/cis_mappings.go` to add CIS control detection rules.

---

## CIS Kubernetes v1.8 Controls

elf-owl detects compliance with:

- **48 Automated Controls**: Via eBPF + K8s API
- **9 Manual Controls**: Flagged for manual review

### Automated Controls (Examples)

- CIS 4.5.1: Privileged container detection
- CIS 4.5.2: Root user execution detection
- CIS 4.5.3: Linux capability usage detection
- CIS 4.5.5: Root filesystem write detection
- CIS 4.1.1: Default ServiceAccount detection
- CIS 4.6.1: Default deny NetworkPolicy detection

### Manual Controls

- CIS 1.1-1.5: API server configuration (requires node access)
- CIS 4.2: Kubelet configuration (requires node access)

See [CIS_CONTROLS.md](docs/CIS_CONTROLS.md) for complete reference.

---

## Security Considerations

### Evidence Protection

All evidence is:
- **Signed** with HMAC-SHA256 for integrity
- **Encrypted** with AES-256-GCM for confidentiality
- **Batched** and compressed for efficiency
- **Pushed** over TLS 1.3+ only

### RBAC

The agent requires minimal read-only permissions:
- Read pods and pod specs
- Read deployments/statefulsets
- Read NetworkPolicies
- Read RBAC policies
- Read nodes
- Watch ConfigMaps (for rules)

**NO** permission to:
- Modify resources
- Delete resources
- Execute commands
- Access secrets (except JWT token)

See [deploy/helm/templates/clusterrole.yaml](deploy/helm/templates/clusterrole.yaml) for full RBAC definition.

---

## Troubleshooting

### Agent won't start

Check logs:
```bash
kubectl logs -n elf-owl-system -l app=elf-owl
```

Verify configuration:
```bash
kubectl get configmap -n elf-owl-system elf-owl-config -o yaml
```

### Missing K8s metadata

Verify RBAC:
```bash
kubectl auth can-i get pods --as=system:serviceaccount:elf-owl-system:elf-owl
```

### No violations detected

1. Verify cilium/ebpf monitors are running (check agent logs for "monitor started")
2. Check rule definitions in ConfigMap
3. Enable debug logging: `export OWL_LOG_LEVEL=debug`

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

---

## License

[Elastic License 2.0](LICENSE)

---

## Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Version:** 0.1.0
**Last Updated:** December 26, 2025
**Next Milestone:** Week 2 - Event Processing Pipeline
