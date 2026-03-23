#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
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
  stopped=0
  tracked_pid=''

  if ! sudo test -f '$VM_PID_FILE'; then
    echo 'No PID file found.'
  else
    pid=\$(sudo cat '$VM_PID_FILE')
    tracked_pid=\"\${pid}\"
    if [[ -n \"\${pid}\" ]] && sudo kill -0 \"\${pid}\" 2>/dev/null; then
      sudo kill \"\${pid}\" || true
      echo \"Stopped elf-owl (PID \${pid}).\"
      stopped=1
    else
      echo 'PID file exists but process is not running.'
    fi
  fi

  # Also stop any orphaned elf-owl process.
  extra_pids=\$(sudo pgrep -x elf-owl || true)
  if [[ -n \"\${extra_pids}\" ]]; then
    for p in \${extra_pids}; do
      if [[ -n \"\${tracked_pid}\" && \"\${p}\" == \"\${tracked_pid}\" ]]; then
        continue
      fi
      sudo kill \"\${p}\" || true
      echo \"Stopped orphan elf-owl (PID \${p}).\"
      stopped=1
    done
  fi

  sudo rm -f '$VM_PID_FILE'

  if [[ \"\${stopped}\" -eq 0 ]]; then
    echo 'No running elf-owl process found.'
  fi
"
