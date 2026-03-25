#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_PROJECT_DIR="/home/ubuntu/work/owl-agent"
SYNC=0
PULL=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --project-dir <vm-path>   VM project directory (default: ${VM_PROJECT_DIR})
  --sync                    Sync local source into VM before build
  --pull                    Pull built .o files back into local repo
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --project-dir) VM_PROJECT_DIR="$2"; shift 2 ;;
    --sync) SYNC=1; shift ;;
    --pull) PULL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$SYNC" -eq 1 ]]; then
  "$SCRIPT_DIR/sync-vm-src.sh" --name "$VM_NAME" --project-dir "$VM_PROJECT_DIR"
fi

multipass start "$VM_NAME" >/dev/null 2>&1 || true

echo "[ebpf-build] Ensuring VM build dependencies..."
# ANCHOR: VM CO-RE deps - Feature: bpftool install - Mar 25, 2026
multipass exec "$VM_NAME" -- bash -lc '
  set -euo pipefail
  sudo apt-get update -y >/dev/null
  sudo apt-get install -y clang llvm make libbpf-dev linux-libc-dev bpftool >/dev/null
'

echo "[ebpf-build] Building C eBPF programs in VM..."
# ANCHOR: BTF preflight - Safety: CO-RE guard - Mar 25, 2026
multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "[ebpf-build] Missing /sys/kernel/btf/vmlinux (BTF not enabled)" >&2
    exit 1
  fi
"

multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  cd '$VM_PROJECT_DIR/pkg/ebpf/programs'
  make clean
  make
  ls -l bin/*.o
  file bin/*.o
"

if [[ "$PULL" -eq 1 ]]; then
  echo "[ebpf-build] Pulling VM-built bytecode into local repository..."
  for f in process network file capability dns; do
    multipass transfer "$VM_NAME:$VM_PROJECT_DIR/pkg/ebpf/programs/bin/${f}.o" "$PROJECT_ROOT/pkg/ebpf/programs/bin/${f}.o"
  done
  ls -l "$PROJECT_ROOT"/pkg/ebpf/programs/bin/*.o
fi

echo "[ebpf-build] Done."
