#!/usr/bin/env bash
set -euo pipefail

# ANCHOR: vmlinux.h generation - Feature: CO-RE build helper - Mar 25, 2026
# Generates pkg/ebpf/programs/vmlinux.h from kernel BTF via bpftool.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_OUT="${PROJECT_ROOT}/pkg/ebpf/programs/vmlinux.h"
DEFAULT_BTF="/sys/kernel/btf/vmlinux"

BTF_PATH="${DEFAULT_BTF}"
OUT_PATH="${DEFAULT_OUT}"
USE_SUDO=0

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --btf <path>      Path to kernel BTF (default: ${DEFAULT_BTF})
  --out <path>      Output path for vmlinux.h (default: ${DEFAULT_OUT})
  --sudo            Run bpftool via sudo
  -h, --help        Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --btf) BTF_PATH="$2"; shift 2 ;;
    --out) OUT_PATH="$2"; shift 2 ;;
    --sudo) USE_SUDO=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ ! -f "$BTF_PATH" ]]; then
  echo "[vmlinux] BTF file not found: $BTF_PATH" >&2
  echo "[vmlinux] Ensure a BTF-enabled kernel or pass --btf <path>." >&2
  exit 1
fi

OUT_DIR="$(dirname "$OUT_PATH")"
mkdir -p "$OUT_DIR"

cmd=(bpftool btf dump file "$BTF_PATH" format c)
if [[ "$USE_SUDO" -eq 1 ]]; then
  cmd=(sudo "${cmd[@]}")
fi

"${cmd[@]}" > "$OUT_PATH"

if [[ ! -s "$OUT_PATH" ]]; then
  echo "[vmlinux] Failed to generate vmlinux.h at $OUT_PATH" >&2
  exit 1
fi

echo "[vmlinux] Generated $OUT_PATH"
