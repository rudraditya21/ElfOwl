#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_LOG_FILE="/var/log/elf-owl/agent.log"

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
  if ! sudo test -f '$VM_LOG_FILE'; then
    echo 'Log file not found: $VM_LOG_FILE'
    exit 1
  fi

  echo '=== Log-Based Event Summary ==='
  echo -n 'process events:     '
  sudo grep -c 'process event sent' '$VM_LOG_FILE' || true
  echo -n 'network events:     '
  sudo grep -c 'network event sent' '$VM_LOG_FILE' || true
  echo -n 'dns events:         '
  sudo grep -c 'dns event sent' '$VM_LOG_FILE' || true
  echo -n 'file events:        '
  sudo grep -c 'file event sent' '$VM_LOG_FILE' || true
  echo -n 'capability events:  '
  sudo grep -c 'capability event sent' '$VM_LOG_FILE' || true
  echo -n 'tls events:         '
  sudo grep -c 'tls event' '$VM_LOG_FILE' || true
  echo -n 'webhook events:     '
  sudo grep -c 'webhook event received' '$VM_LOG_FILE' || true
  echo -n 'violations detected:'
  sudo grep -c 'CIS violation detected' '$VM_LOG_FILE' || true

  echo
  echo 'Tip: event sent lines are debug-level; start with --log-level debug for full event visibility.'
"
