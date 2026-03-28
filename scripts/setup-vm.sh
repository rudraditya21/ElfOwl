#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
CPUS="4"
MEMORY="8G"
DISK="30G"
IMAGE="24.04"
GO_VERSION="1.23.0"
VM_PROJECT_DIR="/home/ubuntu/work/owl-agent"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ANCHOR: VM exec readiness wait - Fix: post-launch SSH race - Mar 28, 2026
# Multipass can report a VM as launched/running before exec/SSH is reachable.
wait_for_vm_exec() {
  local attempts="${1:-45}"
  local sleep_seconds="${2:-2}"
  local try

  for try in $(seq 1 "$attempts"); do
    if multipass exec "$VM_NAME" -- bash -lc "true" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$sleep_seconds"
  done

  return 1
}

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>        VM name (default: ${VM_NAME})
  --cpus <n>              vCPU count (default: ${CPUS})
  --memory <size>         RAM, e.g. 8G (default: ${MEMORY})
  --disk <size>           Disk, e.g. 30G (default: ${DISK})
  --image <image>         Multipass image (default: ${IMAGE})
  --go-version <version>  Go version to install (default: ${GO_VERSION})
  --project-dir <vm-path> VM project directory (default: ${VM_PROJECT_DIR})
  -h, --help              Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --cpus) CPUS="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --disk) DISK="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --go-version) GO_VERSION="$2"; shift 2 ;;
    --project-dir) VM_PROJECT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if ! command -v multipass >/dev/null 2>&1; then
  echo "multipass is required but not installed."
  exit 1
fi

if ! multipass info "$VM_NAME" >/dev/null 2>&1; then
  echo "[setup] Launching VM '${VM_NAME}' (${IMAGE}, ${CPUS} CPU, ${MEMORY} RAM, ${DISK} disk)..."
  multipass launch "$IMAGE" --name "$VM_NAME" --cpus "$CPUS" --memory "$MEMORY" --disk "$DISK"
else
  echo "[setup] VM '${VM_NAME}' already exists."
fi

echo "[setup] Starting VM '${VM_NAME}'..."
multipass start "$VM_NAME" >/dev/null 2>&1 || true

echo "[setup] Waiting for VM exec readiness..."
if ! wait_for_vm_exec 45 2; then
  echo "[setup] VM '${VM_NAME}' did not become reachable via multipass exec in time."
  exit 1
fi

echo "[setup] Installing base packages in VM..."
multipass exec "$VM_NAME" -- bash -lc '
  set -euo pipefail
  sudo apt-get update -y
  sudo apt-get install -y curl ca-certificates git make gcc clang llvm jq strace dnsutils libbpf-dev linux-libc-dev
'

echo "[setup] Installing Go ${GO_VERSION} in VM..."
multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  cd /tmp
  CURRENT=\$(/usr/local/go/bin/go version 2>/dev/null | awk '{print \$3}' || true)
  TARGET='go${GO_VERSION}'
  if [[ \"\${CURRENT}\" != \"\${TARGET}\" ]]; then
    TMP_TGZ=/tmp/go${GO_VERSION}.linux-amd64.tar.gz
    curl -fsSL -o \"\${TMP_TGZ}\" \"https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz\"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf \"\${TMP_TGZ}\"
    rm -f \"\${TMP_TGZ}\"
  fi
  if ! grep -q '/usr/local/go/bin' ~/.profile 2>/dev/null; then
    echo 'export PATH=/usr/local/go/bin:\$PATH' >> ~/.profile
  fi
  export PATH=/usr/local/go/bin:\$PATH
  go version
"

echo "[setup] Syncing source into VM..."
"$SCRIPT_DIR/sync-vm-src.sh" --name "$VM_NAME" --project-dir "$VM_PROJECT_DIR"

echo "[setup] Done."
echo "Next:"
echo "  scripts/start-vm.sh --name ${VM_NAME}"
echo "  scripts/test-ebpf-kernel.sh --name ${VM_NAME} --sync --pull"
echo "  scripts/test-events.sh --name ${VM_NAME}"
echo "  scripts/start-agent.sh --name ${VM_NAME} --kubeconfig /path/in/vm/config"
