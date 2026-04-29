#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_LOG_FILE="/var/log/elf-owl/agent.log"
VM_PID_FILE="/var/run/elf-owl/agent.pid"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--name <vm-name>]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

multipass start "$VM_NAME" >/dev/null 2>&1 || true

multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail

  echo '=== Process Status ==='
  if sudo test -f '$VM_PID_FILE'; then
    pid=\$(sudo cat '$VM_PID_FILE')
    if [[ -n \"\${pid}\" ]] && sudo kill -0 \"\${pid}\" 2>/dev/null; then
      echo \"running (PID \${pid})\"
    else
      echo 'not running (stale pid file)'
    fi
  else
    echo 'not running (no pid file)'
  fi

  echo
  echo '=== Health (/health) ==='
  curl -sf http://127.0.0.1:9091/health || echo 'health endpoint unavailable'

  echo
  echo '=== Webhook Pusher (outbound) ==='
  if sudo grep -q 'webhook pusher started' '$VM_LOG_FILE' 2>/dev/null; then
    target="$(sudo grep 'webhook pusher started' '$VM_LOG_FILE' | tail -1 | grep -oP '(?<="target":")[^"]+' || true)"
    echo "enabled — pushing to ${target:-<configured target>}"
    pushes="$(sudo grep -c 'webhook batch pushed' '$VM_LOG_FILE' 2>/dev/null || echo 0)"
    echo "batches pushed so far: ${pushes}"
  else
    echo 'disabled (start with --enable-webhook --webhook-url <url> to activate)'
  fi

  echo
  echo '=== Key Metrics (/metrics) ==='
  curl -sf http://127.0.0.1:9090/metrics | grep -E '^elf_owl_(events_processed_total|violations_found_total|events_buffered|push_success_total|push_failure_total|enrichment_errors_total|rule_match_errors_total)' || echo 'metrics unavailable'

  echo
  echo '=== Recent Errors ==='
  if sudo test -f '$VM_LOG_FILE'; then
    sudo grep -E '\"level\":\"(error|fatal)\"|failed' '$VM_LOG_FILE' | tail -n 20 || true
  else
    echo 'log file not found'
  fi
"
