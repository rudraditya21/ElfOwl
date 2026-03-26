#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_PROJECT_DIR="/home/ubuntu/work/owl-agent"
KEEP_ARCHIVE=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# ANCHOR: Local archive path - Fix: Multipass snap sandbox - Mar 25, 2026
# Multipass snap has restricted filesystem access due to confinement. It can access
# the home directory and current working directory, but not /tmp. Create archive in
# the project root directory where it's accessible to multipass transfer.
LOCAL_ARCHIVE="${PROJECT_ROOT}/.owl-agent-src.tgz"
VM_ARCHIVE="/tmp/owl-agent-src.tgz"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --project-dir <vm-path>   Destination project dir in VM (default: ${VM_PROJECT_DIR})
  --keep-archive            Keep local temporary archive /tmp/owl-agent-src.tgz
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --project-dir) VM_PROJECT_DIR="$2"; shift 2 ;;
    --keep-archive) KEEP_ARCHIVE=1; shift ;;
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

multipass start "$VM_NAME" >/dev/null 2>&1 || true

echo "[sync] Creating source archive..."
COPYFILE_DISABLE=1 tar -czf "$LOCAL_ARCHIVE" \
  --exclude='.git' \
  --exclude='.gocache' \
  --exclude='.gomodcache' \
  --exclude='*.DS_Store' \
  --exclude='.owl-agent-src.tgz' \
  -C "$PROJECT_ROOT/.." "$(basename "$PROJECT_ROOT")"

echo "[sync] Transferring archive to VM..."
multipass transfer "$LOCAL_ARCHIVE" "$VM_NAME:$VM_ARCHIVE"

echo "[sync] Extracting in VM to ${VM_PROJECT_DIR}..."
VM_PARENT_DIR="$(dirname "$VM_PROJECT_DIR")"
VM_BASENAME="$(basename "$VM_PROJECT_DIR")"

multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  mkdir -p '$VM_PARENT_DIR'
  rm -rf '$VM_PROJECT_DIR'
  tar --warning=no-unknown-keyword -xzf '$VM_ARCHIVE' -C '$VM_PARENT_DIR'
  if [[ '$VM_BASENAME' != '$(basename "$PROJECT_ROOT")' ]]; then
    mv '$VM_PARENT_DIR/$(basename "$PROJECT_ROOT")' '$VM_PROJECT_DIR'
  fi
  rm -f '$VM_ARCHIVE'
  test -r '$VM_PROJECT_DIR/go.mod'
"

if [[ "$KEEP_ARCHIVE" -eq 0 ]]; then
  rm -f "$LOCAL_ARCHIVE"
fi

echo "[sync] Done. VM project dir: ${VM_PROJECT_DIR}"
