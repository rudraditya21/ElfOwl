# elf-owl Installation Guide

This guide is synced with current repository scripts, paths, and runtime flags.

---

## 1) Prerequisites

### Host requirements

- Linux kernel with eBPF support (5.8+ recommended).
- Go 1.23.x for local builds.
- For VM workflow: Multipass installed on host.

### Repository layout assumptions

- Config file: `config/elf-owl.yaml`
- Rule file: `config/rules/cis-controls.yaml`
- VM project path (default): `/home/ubuntu/work/owl-agent`

---

## 2) Recommended Installation: Multipass VM

This is the most reproducible dev/test path.

### 2.1 Create/provision VM

```bash
scripts/setup-vm.sh --name elf-owl-dev --cpus 2 --memory 6G --disk 20G
```

### 2.2 Install k3s in VM (Kubernetes mode)

```bash
scripts/setup-k8s-vm.sh --name elf-owl-dev --kubeconfig /home/ubuntu/.kube/config
```

### 2.3 Build eBPF programs in VM

```bash
scripts/build-ebpf-vm.sh --name elf-owl-dev --sync --pull
```

### 2.4 Start agent in VM

Kubernetes mode:

```bash
scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug --kubeconfig /home/ubuntu/.kube/config
```

No-K8s mode:

```bash
scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug --no-k8s
```

### 2.5 Validate installation

```bash
scripts/check-state.sh --name elf-owl-dev
scripts/check-logs.sh --name elf-owl-dev --type startup --lines 120
scripts/event-summary.sh --name elf-owl-dev
```

Smoke/event validation:

```bash
scripts/test-events.sh --name elf-owl-dev --sync
scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild --sample-lines 5
scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild --sample-lines 5 --without-k8s
```

---

## 3) Linux Host Installation (No VM)

For direct host setup, use [`SETUP_LINUX.md`](../SETUP_LINUX.md).

Minimal local build:

```bash
go mod download
go build -mod=mod -o elf-owl ./cmd/elf-owl
```

Run (example, no-K8s mode):

```bash
sudo env \
  OWL_CLUSTER_ID=standalone \
  OWL_NODE_NAME="$(hostname)" \
  OWL_API_ENDPOINT=https://owl-saas.example.com \
  OWL_JWT_TOKEN=YOUR_TOKEN \
  OWL_K8S_IN_CLUSTER=false \
  OWL_KUBERNETES_METADATA=false \
  OWL_KUBERNETES_ONLY=false \
  OWL_LOG_LEVEL=debug \
  ./elf-owl
```

---

## 4) Kubernetes Deployment

### 4.1 Helm (local chart in repo)

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

Enable starter ConfigMap rules (optional):

```bash
helm upgrade --install elf-owl ./deploy/helm \
  --namespace elf-owl-system \
  --set rules.configMap.enabled=true
```

### 4.2 Kustomize

```bash
kubectl apply -k deploy/kustomize/overlays/production
# Optional starter rules overlay
kubectl apply -k deploy/kustomize/overlays/with-rules
```

### 4.3 Verify deployment

```bash
kubectl get daemonset -n elf-owl-system elf-owl
kubectl get pods -n elf-owl-system -l app=elf-owl
kubectl logs -n elf-owl-system -l app=elf-owl --tail=80
```

---

## 5) Runtime Endpoints

Health endpoint:

```bash
curl -sf http://127.0.0.1:9091/health
```

Metrics endpoint:

```bash
curl -sf http://127.0.0.1:9090/metrics | grep '^elf_owl_' | head
```

---

## 6) Environment Variables (Current)

Supported overrides used by the current code and scripts:

- `OWL_CLUSTER_ID`
- `OWL_NODE_NAME`
- `OWL_API_ENDPOINT`
- `OWL_JWT_TOKEN`
- `OWL_LOG_LEVEL`
- `OWL_K8S_IN_CLUSTER`
- `OWL_KUBERNETES_METADATA`
- `OWL_KUBERNETES_ONLY`
- `ELF_OWL_SIGNING_KEY`
- `ELF_OWL_ENCRYPTION_KEY`
- `KUBECONFIG` (for out-of-cluster K8s mode)

Configuration file load order:

1. `./config/elf-owl.yaml`
2. `/etc/elf-owl/elf-owl.yaml`
3. `$HOME/.config/elf-owl/elf-owl.yaml`

---

## 7) Common Issues

### Agent exits immediately in VM

Use one of:

- `--kubeconfig /home/ubuntu/.kube/config`
- `--no-k8s`

Then inspect:

```bash
scripts/check-logs.sh --name elf-owl-dev --type startup --lines 120
```

### Kubernetes disabled but events dropped

This indicates invalid mode combination. Use:

```bash
OWL_KUBERNETES_METADATA=false
OWL_KUBERNETES_ONLY=false
```

### k3s unavailable in VM

```bash
scripts/setup-k8s-vm.sh --name elf-owl-dev --kubeconfig /home/ubuntu/.kube/config
scripts/vm-exec.sh --name elf-owl-dev --no-cd -- bash -lc 'sudo systemctl is-active k3s && sudo k3s kubectl get nodes -o wide'
```
