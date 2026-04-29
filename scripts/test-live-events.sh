#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
KUBECONFIG_PATH="/home/ubuntu/.kube/config"
SYNC=0
REBUILD=0
LOG_LEVEL="debug"
SAMPLE_LINES="5"
ENSURE_K8S=1
RUN_NO_K8S=0
ENABLE_WEBHOOK=0

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
  --without-k8s             Start agent in no-k8s mode (no K8s client/metadata)
  --enable-webhook          Enable inbound webhook on :9093 and run smoke test
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
    --without-k8s) RUN_NO_K8S=1; ENSURE_K8S=0; shift ;;
    --enable-webhook) ENABLE_WEBHOOK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$RUN_NO_K8S" -eq 1 ]] && [[ -n "${KUBECONFIG_PATH}" ]]; then
  # keep user-provided value ignored in --without-k8s mode to avoid mixed signals
  KUBECONFIG_PATH=""
fi

if [[ "$ENSURE_K8S" -eq 1 ]]; then
  "$SCRIPT_DIR/setup-k8s-vm.sh" --name "$VM_NAME" --kubeconfig "$KUBECONFIG_PATH"
fi

"$SCRIPT_DIR/stop-agent.sh" --name "$VM_NAME" || true
"$SCRIPT_DIR/vm-exec.sh" --name "$VM_NAME" --no-cd -- bash -lc "sudo truncate -s 0 /var/log/elf-owl/agent.log || true"

start_args=(--name "$VM_NAME" --log-level "$LOG_LEVEL")
if [[ "$RUN_NO_K8S" -eq 1 ]]; then
  start_args+=(--no-k8s)
else
  start_args+=(--kubeconfig "$KUBECONFIG_PATH")
fi
if [[ "$SYNC" -eq 1 ]]; then
  start_args+=(--sync)
fi
if [[ "$REBUILD" -eq 1 ]]; then
  start_args+=(--rebuild)
fi
if [[ "$ENABLE_WEBHOOK" -eq 1 ]]; then
  start_args+=(--enable-webhook)
fi

"$SCRIPT_DIR/start-agent.sh" "${start_args[@]}"
sleep 2

if [[ "$RUN_NO_K8S" -eq 1 ]]; then
  echo "[test] Running no-k8s smoke assertions..."
  "$SCRIPT_DIR/vm-exec.sh" --name "$VM_NAME" --no-cd -- bash -lc "
    set -euo pipefail
    curl -sf http://127.0.0.1:9091/health >/dev/null
    if ! sudo grep -q 'running without Kubernetes client' /var/log/elf-owl/agent.log; then
      echo 'expected no-k8s startup log not found'
      exit 1
    fi
    if sudo grep -q 'failed to create kubernetes client' /var/log/elf-owl/agent.log; then
      echo 'unexpected kubernetes client init failure log found'
      exit 1
    fi
  "
fi

generate_args=(--name "$VM_NAME")
if [[ "$ENABLE_WEBHOOK" -eq 1 ]]; then
  generate_args+=(--webhook)
fi
"$SCRIPT_DIR/generate-events.sh" "${generate_args[@]}"
sleep 2

if [[ "$ENABLE_WEBHOOK" -eq 1 ]]; then
  echo "[test] Running webhook smoke assertions..."
  "$SCRIPT_DIR/vm-exec.sh" --name "$VM_NAME" --no-cd -- bash -lc "
    set -euo pipefail
    # Valid type must return 202
    response=\$(curl -sf -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:9093/webhook/events \
      -H 'Content-Type: application/json' \
      -d '{\"type\":\"tls\",\"payload\":{},\"timestamp\":\"2000-01-01T00:00:00Z\"}')
    if [[ \"\$response\" != '202' ]]; then
      echo \"expected HTTP 202 from webhook, got \$response\"
      exit 1
    fi
    # Unknown type must return 400
    bad=\$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:9093/webhook/events \
      -H 'Content-Type: application/json' \
      -d '{\"type\":\"unknown_type\",\"payload\":{}}')
    if [[ \"\$bad\" != '400' ]]; then
      echo \"expected HTTP 400 for unknown type, got \$bad\"
      exit 1
    fi
    echo 'webhook smoke: PASS'
  "
fi

"$SCRIPT_DIR/check-state.sh" --name "$VM_NAME"
echo
"$SCRIPT_DIR/event-summary.sh" --name "$VM_NAME"
echo
"$SCRIPT_DIR/check-event-values.sh" --name "$VM_NAME" --lines "$SAMPLE_LINES"
