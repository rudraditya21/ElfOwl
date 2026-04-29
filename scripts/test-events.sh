#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_PROJECT_DIR="/home/ubuntu/work/owl-agent"
SYNC=0
RUN_FULL=0
RUN_KERNEL=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --project-dir <vm-path>   VM project directory (default: ${VM_PROJECT_DIR})
  --sync                    Sync source to VM before testing
  --kernel                  Run root kernel eBPF integration matrix (scripts/test-ebpf-kernel.sh)
  --full                    Also run full repository go test ./...
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --project-dir) VM_PROJECT_DIR="$2"; shift 2 ;;
    --sync) SYNC=1; shift ;;
    --kernel) RUN_KERNEL=1; shift ;;
    --full) RUN_FULL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$SYNC" -eq 1 ]]; then
  "$SCRIPT_DIR/sync-vm-src.sh" --name "$VM_NAME" --project-dir "$VM_PROJECT_DIR"
fi

multipass start "$VM_NAME" >/dev/null 2>&1 || true

TS="$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="${VM_PROJECT_DIR}/.vm-test-results/${TS}"

multipass exec "$VM_NAME" -- bash -lc "mkdir -p '$RESULTS_DIR'"

run_test() {
  local name="$1"
  local cmd="$2"
  local status=""
  local status_file="${RESULTS_DIR}/${name}.status"
  set +e
  multipass exec "$VM_NAME" -- bash -lc "
    set -euo pipefail
    export PATH=/usr/local/go/bin:\$PATH
    cd '$VM_PROJECT_DIR'
    mkdir -p '$RESULTS_DIR'
    rm -f '$status_file'
    GOCACHE=/tmp/elf-owl-gocache GOMODCACHE=/tmp/elf-owl-gomodcache ${cmd} | tee '$RESULTS_DIR/${name}.log'
    status=\${PIPESTATUS[0]}
    echo \"\$status\" > '$status_file'
    exit 0
  "
  local exec_status=$?
  status="$(multipass exec "$VM_NAME" -- bash -lc "cat '$status_file' 2>/dev/null || true")"
  set -e
  if [[ "$status" =~ ^[0-9]+$ ]]; then
    return "$status"
  fi
  if [[ "$exec_status" =~ ^[0-9]+$ ]]; then
    return "$exec_status"
  fi
  return 1
}

KERNEL_STATUS="SKIPPED"
if [[ "$RUN_KERNEL" -eq 1 ]]; then
  echo "[test] Running kernel eBPF event tests..."
  kernel_args=(--name "$VM_NAME" --project-dir "$VM_PROJECT_DIR")
  # Source was already synced above when --sync is set.
  # A second sync here would replace the VM project directory and remove RESULTS_DIR.
  if "$SCRIPT_DIR/test-ebpf-kernel.sh" "${kernel_args[@]}"; then
    KERNEL_STATUS=0
  else
    KERNEL_STATUS=$?
  fi
fi

echo "[test] Running JA3 parser tests..."
if run_test ja3 'go test -mod=mod -v ./pkg/ja3'; then
  JA3_STATUS=0
else
  JA3_STATUS=$?
fi

echo "[test] Running eBPF monitor/event tests..."
if run_test ebpf 'go test -mod=mod -v ./pkg/ebpf'; then
  EBPF_STATUS=0
else
  EBPF_STATUS=$?
fi

echo "[test] Running rules integration tests..."
if run_test rules_integration 'go test -mod=mod -v ./pkg/rules -run TestIntegration'; then
  RULES_STATUS=0
else
  RULES_STATUS=$?
fi

echo "[test] Running Kubernetes compliance event tests..."
if run_test compliance_events 'go test -mod=mod -v ./pkg/agent -run "TestBuildPodSpecEventsMultiContainer|TestBuildNetworkPolicyEvent"'; then
  COMPLIANCE_STATUS=0
else
  COMPLIANCE_STATUS=$?
fi

echo "[test] Running no-k8s handler behavior tests..."
if run_test no_k8s_handlers 'go test -mod=mod -v ./pkg/agent -run "TestHandlerFallbackWhenKubernetesOnlyFalse|TestHandlerRuntimeBehaviorMatrix"'; then
  NO_K8S_STATUS=0
else
  NO_K8S_STATUS=$?
fi

echo "[test] Running TLS handler tests..."
if run_test tls_webhook 'go test -mod=mod -v ./pkg/agent -run "TestTLS"'; then
  TLS_WEBHOOK_STATUS=0
else
  TLS_WEBHOOK_STATUS=$?
fi

FULL_STATUS="SKIPPED"
if [[ "$RUN_FULL" -eq 1 ]]; then
  echo "[test] Running full repository tests..."
  if run_test full 'go test -mod=mod ./...'; then
    FULL_STATUS=0
  else
    FULL_STATUS=$?
  fi
fi

matrix_check() {
  local label="$1"
  local pattern="$2"
  local file="$3"
  if multipass exec "$VM_NAME" -- bash -lc "grep -qE -- '$pattern' '$file'"; then
    printf '%-16s %s\n' "$label" "PASS"
  else
    printf '%-16s %s\n' "$label" "FAIL"
  fi
}

echo
echo "=== Event Path Matrix (from VM tests) ==="
EBPF_LOG="${RESULTS_DIR}/ebpf.log"
JA3_LOG="${RESULTS_DIR}/ja3.log"
RULES_LOG="${RESULTS_DIR}/rules_integration.log"
COMPLIANCE_LOG="${RESULTS_DIR}/compliance_events.log"
NO_K8S_LOG="${RESULTS_DIR}/no_k8s_handlers.log"
TLS_WEBHOOK_LOG="${RESULTS_DIR}/tls_webhook.log"

matrix_check "process" 'ProcessMonitor_produces_process_execution_events|TestIntegrationRootProcessExecution.*PASS' "$EBPF_LOG"
matrix_check "network" 'NetworkMonitor_produces_network_connection_events|TestIntegrationNetworkPolicyViolation.*PASS' "$EBPF_LOG"
matrix_check "dns" 'DNSMonitor_produces_dns_query_events|TestIntegrationDNSExfiltration.*PASS' "$EBPF_LOG"
matrix_check "file" 'FileMonitor_produces_file_access_events' "$EBPF_LOG"
matrix_check "capability" 'CapabilityMonitor_produces_capability_usage_events|TestIntegrationCapabilityViolation.*PASS' "$EBPF_LOG"
matrix_check "tls_ja3" '--- PASS: TestParseJA3Metadata' "$JA3_LOG"
matrix_check "tls_ebpf" 'TLSMonitor_produces_tls_events' "$EBPF_LOG"
matrix_check "webhook" '--- PASS: TestTLS|TestWebhookPusher' "$TLS_WEBHOOK_LOG"
matrix_check "pod_spec" '--- PASS: TestBuildPodSpecEventsMultiContainer' "$COMPLIANCE_LOG"
matrix_check "net_policy" '--- PASS: TestBuildNetworkPolicyEvent' "$COMPLIANCE_LOG"
matrix_check "no_k8s" '--- PASS: TestHandlerFallbackWhenKubernetesOnlyFalse|--- PASS: TestHandlerRuntimeBehaviorMatrix' "$NO_K8S_LOG"

# Rules-specific status checks
if [[ "$RULES_STATUS" != "0" ]]; then
  echo
  echo "Rules integration suite status: FAIL (exit ${RULES_STATUS})"
  multipass exec "$VM_NAME" -- bash -lc "grep -E '^=== RUN|^--- (PASS|FAIL)' '$RULES_LOG' | tail -n 80"
else
  echo
  echo "Rules integration suite status: PASS"
fi

if [[ "$COMPLIANCE_STATUS" != "0" ]]; then
  echo
  echo "Compliance event suite status: FAIL (exit ${COMPLIANCE_STATUS})"
  multipass exec "$VM_NAME" -- bash -lc "grep -E '^=== RUN|^--- (PASS|FAIL)' '$COMPLIANCE_LOG' | tail -n 80"
else
  echo
  echo "Compliance event suite status: PASS"
fi

if [[ "$NO_K8S_STATUS" != "0" ]]; then
  echo
  echo "No-k8s handler suite status: FAIL (exit ${NO_K8S_STATUS})"
  multipass exec "$VM_NAME" -- bash -lc "grep -E '^=== RUN|^--- (PASS|FAIL)' '$NO_K8S_LOG' | tail -n 80"
else
  echo
  echo "No-k8s handler suite status: PASS"
fi

echo
echo "=== Test Status ==="
echo "ja3 parser tests:      ${JA3_STATUS}"
echo "ebpf tests:            ${EBPF_STATUS}"
echo "rules integration:     ${RULES_STATUS}"
echo "compliance events:     ${COMPLIANCE_STATUS}"
echo "no-k8s handlers:       ${NO_K8S_STATUS}"
echo "tls/webhook handlers:  ${TLS_WEBHOOK_STATUS}"
echo "kernel eBPF tests:     ${KERNEL_STATUS}"
echo "full repository tests: ${FULL_STATUS}"
echo "results dir:           ${RESULTS_DIR}"

exit_code=0
if [[ "$JA3_STATUS" != "0" ]]; then
  exit_code=1
fi
if [[ "$EBPF_STATUS" != "0" ]]; then
  exit_code=1
fi
if [[ "$RULES_STATUS" != "0" ]]; then
  exit_code=1
fi
if [[ "$COMPLIANCE_STATUS" != "0" ]]; then
  exit_code=1
fi
if [[ "$NO_K8S_STATUS" != "0" ]]; then
  exit_code=1
fi
if [[ "$TLS_WEBHOOK_STATUS" != "0" ]]; then
  exit_code=1
fi
if [[ "$RUN_KERNEL" -eq 1 && "$KERNEL_STATUS" != "0" ]]; then
  exit_code=1
fi
if [[ "$RUN_FULL" -eq 1 && "$FULL_STATUS" != "0" ]]; then
  exit_code=1
fi

exit "$exit_code"
