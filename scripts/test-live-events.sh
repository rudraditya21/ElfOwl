#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
KUBECONFIG_PATH="/home/ubuntu/.kube/config"
SYNC=0
REBUILD=0
LOG_LEVEL="debug"
SAMPLE_LINES="5"
ENSURE_K8S=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --kubeconfig <vm-path>    Kubeconfig path in VM (default: ${KUBECONFIG_PATH})
  --sync                    Sync source into VM before starting agent
  --rebuild                 Rebuild agent binary before start
  --log-level <level>       Agent log level (default: ${LOG_LEVEL})
  --sample-lines <n>        Sample lines per event type (default: ${SAMPLE_LINES})
  --no-k8s-setup            Do not run setup-k8s-vm.sh
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --kubeconfig) KUBECONFIG_PATH="$2"; shift 2 ;;
    --sync) SYNC=1; shift ;;
    --rebuild) REBUILD=1; shift ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    --sample-lines) SAMPLE_LINES="$2"; shift 2 ;;
    --no-k8s-setup) ENSURE_K8S=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$ENSURE_K8S" -eq 1 ]]; then
  "$SCRIPT_DIR/setup-k8s-vm.sh" --name "$VM_NAME" --kubeconfig "$KUBECONFIG_PATH"
fi

"$SCRIPT_DIR/stop-agent.sh" --name "$VM_NAME" || true
"$SCRIPT_DIR/vm-exec.sh" --name "$VM_NAME" --no-cd -- bash -lc "sudo truncate -s 0 /var/log/elf-owl/agent.log || true"

start_args=(--name "$VM_NAME" --kubeconfig "$KUBECONFIG_PATH" --log-level "$LOG_LEVEL")
if [[ "$SYNC" -eq 1 ]]; then
  start_args+=(--sync)
fi
if [[ "$REBUILD" -eq 1 ]]; then
  start_args+=(--rebuild)
fi

"$SCRIPT_DIR/start-agent.sh" "${start_args[@]}"
sleep 2

"$SCRIPT_DIR/generate-events.sh" --name "$VM_NAME"
sleep 2

"$SCRIPT_DIR/check-state.sh" --name "$VM_NAME"
echo
"$SCRIPT_DIR/event-summary.sh" --name "$VM_NAME"
echo
"$SCRIPT_DIR/check-event-values.sh" --name "$VM_NAME" --lines "$SAMPLE_LINES"

