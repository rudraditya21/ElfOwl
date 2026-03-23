#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
LINES="5"
VM_LOG_FILE="/var/log/elf-owl/agent.log"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --lines <n>               Number of sample lines per event type (default: ${LINES})
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --lines) LINES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if ! command -v multipass >/dev/null 2>&1; then
  echo "multipass is required but not installed."
  exit 1
fi

if ! multipass info "$VM_NAME" >/dev/null 2>&1; then
  echo "VM '$VM_NAME' does not exist."
  exit 1
fi

multipass start "$VM_NAME" >/dev/null 2>&1 || true

if ! multipass exec "$VM_NAME" -- bash -lc "sudo test -f '${VM_LOG_FILE}'"; then
  echo "Log file not found: ${VM_LOG_FILE}"
  exit 1
fi

print_type() {
  local label="$1"
  local pattern="$2"

  local count
  count="$(multipass exec "$VM_NAME" -- bash -lc "sudo grep -c -- '${pattern}' '${VM_LOG_FILE}' || true" | tr -d '\r')"

  echo
  echo "=== ${label} (${count}) ==="
  multipass exec "$VM_NAME" -- bash -lc "sudo grep -- '${pattern}' '${VM_LOG_FILE}' | tail -n '${LINES}' || true"
}

echo "=== Event Value Samples (from ${VM_LOG_FILE}) ==="
print_type "process" "process event sent"
print_type "network" "network event sent"
print_type "dns" "dns event sent"
print_type "file" "file event sent"
print_type "capability" "capability event sent"

