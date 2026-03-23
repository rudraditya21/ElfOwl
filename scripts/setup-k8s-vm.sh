#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
KUBECONFIG_PATH="/home/ubuntu/.kube/config"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --kubeconfig <vm-path>    Kubeconfig path inside VM (default: ${KUBECONFIG_PATH})
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --kubeconfig) KUBECONFIG_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if ! command -v multipass >/dev/null 2>&1; then
  echo "multipass is required but not installed."
  exit 1
fi

if ! multipass info "$VM_NAME" >/dev/null 2>&1; then
  echo "VM '$VM_NAME' does not exist. Run scripts/setup-vm.sh first."
  exit 1
fi

echo "[k8s] Starting VM '${VM_NAME}'..."
multipass start "$VM_NAME" >/dev/null 2>&1 || true

echo "[k8s] Installing/ensuring k3s API server..."
multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail

  if ! command -v k3s >/dev/null 2>&1; then
    curl -sfL https://get.k3s.io | sh -
  fi

  sudo systemctl enable --now k3s

  for _ in \$(seq 1 90); do
    if sudo k3s kubectl get nodes >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  if ! sudo k3s kubectl get nodes >/dev/null 2>&1; then
    echo 'k3s did not become ready in time'
    exit 1
  fi

  sudo mkdir -p \"\$(dirname '${KUBECONFIG_PATH}')\"
  sudo cp /etc/rancher/k3s/k3s.yaml '${KUBECONFIG_PATH}'
  sudo chown ubuntu:ubuntu '${KUBECONFIG_PATH}'
  sudo chmod 600 '${KUBECONFIG_PATH}'
"

echo "[k8s] Cluster status:"
multipass exec "$VM_NAME" -- bash -lc "sudo systemctl is-active k3s && sudo k3s kubectl get nodes -o wide"

echo "[k8s] Kubeconfig ready at: ${KUBECONFIG_PATH}"

