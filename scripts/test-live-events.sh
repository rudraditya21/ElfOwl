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
WEBHOOK_TARGET_URL=""

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
  --enable-webhook          Enable outbound webhook pusher and run smoke test
  --webhook-url <url>       Target URL for outbound push (default: http://127.0.0.1:8888/events)
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
    --webhook-url) WEBHOOK_TARGET_URL="$2"; shift 2 ;;
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
  _webhook_target="${WEBHOOK_TARGET_URL:-http://127.0.0.1:8888/events}"
  start_args+=(--webhook-url "$_webhook_target")
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
"$SCRIPT_DIR/generate-events.sh" "${generate_args[@]}"
sleep 2

if [[ "$ENABLE_WEBHOOK" -eq 1 ]]; then
  echo "[test] Running webhook pusher smoke assertions..."
  _webhook_target="${WEBHOOK_TARGET_URL:-http://127.0.0.1:8888/events}"
  _listener_port="$(echo "$_webhook_target" | grep -oP ':\K[0-9]+(?=/)' || echo 8888)"
  _result_file="/tmp/elf-owl-webhook-smoke-$$"

  # Start a one-shot Python HTTP listener in the background inside the VM.
  # It writes the first received batch to a temp file then exits.
  "$SCRIPT_DIR/vm-exec.sh" --name "$VM_NAME" --no-cd -- bash -lc "
    set -euo pipefail
    python3 - '${_listener_port}' '${_result_file}' <<'PYEOF' &
import sys, http.server, json, os

port   = int(sys.argv[1])
outfile = sys.argv[2]

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        with open(outfile, 'w') as f:
            f.write(body.decode())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')
        raise SystemExit(0)
    def log_message(self, *a): pass

http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF
    echo \$! > /tmp/elf-owl-webhook-listener-pid-$$
  "

  # Give the listener a moment to bind then re-generate a small event burst.
  sleep 1
  "$SCRIPT_DIR/generate-events.sh" --name "$VM_NAME"

  # Wait up to 15 s for the listener to capture a batch.
  "$SCRIPT_DIR/vm-exec.sh" --name "$VM_NAME" --no-cd -- bash -lc "
    set -euo pipefail
    for i in \$(seq 1 15); do
      if [[ -f '${_result_file}' ]]; then break; fi
      sleep 1
    done
    if [[ ! -f '${_result_file}' ]]; then
      echo 'webhook smoke: FAIL — no batch received within 15s'
      # Kill listener if still running
      pid=\$(cat /tmp/elf-owl-webhook-listener-pid-$$ 2>/dev/null || true)
      [[ -n \"\$pid\" ]] && kill \"\$pid\" 2>/dev/null || true
      exit 1
    fi
    batch=\$(cat '${_result_file}')
    count=\$(echo \"\$batch\" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d))')
    echo \"webhook smoke: PASS — received batch with \${count} event(s)\"
    rm -f '${_result_file}' /tmp/elf-owl-webhook-listener-pid-$$
  "
fi

"$SCRIPT_DIR/check-state.sh" --name "$VM_NAME"
echo
"$SCRIPT_DIR/event-summary.sh" --name "$VM_NAME"
echo
"$SCRIPT_DIR/check-event-values.sh" --name "$VM_NAME" --lines "$SAMPLE_LINES"
