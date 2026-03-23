#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
DNS_DOMAIN="example.com"
NETWORK_IP="1.1.1.1"
NETWORK_PORT="80"
FILE_PATH="/tmp/elf-owl-file-test.txt"
CAP_MOUNT_PATH="/tmp/elf-owl-capability-test-mount"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --dns-domain <domain>     Domain for synthetic DNS packet (default: ${DNS_DOMAIN})
  --network-ip <ip>         IPv4 destination for TCP connect (default: ${NETWORK_IP})
  --network-port <port>     TCP destination port (default: ${NETWORK_PORT})
  --file-path <path>        File path to read/write in VM (default: ${FILE_PATH})
  --cap-mount <path>        Mount path for capability trigger (default: ${CAP_MOUNT_PATH})
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --dns-domain) DNS_DOMAIN="$2"; shift 2 ;;
    --network-ip) NETWORK_IP="$2"; shift 2 ;;
    --network-port) NETWORK_PORT="$2"; shift 2 ;;
    --file-path) FILE_PATH="$2"; shift 2 ;;
    --cap-mount) CAP_MOUNT_PATH="$2"; shift 2 ;;
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

echo "[events] Triggering process/file/network/dns/capability activity in VM '${VM_NAME}'..."
multipass exec "$VM_NAME" -- \
  env DNS_DOMAIN="$DNS_DOMAIN" NETWORK_IP="$NETWORK_IP" NETWORK_PORT="$NETWORK_PORT" FILE_PATH="$FILE_PATH" CAP_MOUNT_PATH="$CAP_MOUNT_PATH" \
  bash -s <<'EOF'
set -euo pipefail

echo '[events] process: running shell command and binary execution'
/bin/sh -lc 'echo elf-owl-process-trigger >/dev/null'
/usr/bin/id >/dev/null

echo "[events] file: write+read at ${FILE_PATH}"
echo "elf-owl-file-$(date +%s)" > "${FILE_PATH}"
cat "${FILE_PATH}" >/dev/null

echo "[events] network: tcp connect to ${NETWORK_IP}:${NETWORK_PORT}"
timeout 3 bash -lc "cat </dev/null >/dev/tcp/${NETWORK_IP}/${NETWORK_PORT}" || true

echo "[events] dns: sending UDP DNS query packet to 127.0.0.1:53 for ${DNS_DOMAIN}"
python3 - <<'PY'
import os
import random
import socket
import struct

domain = os.environ.get("DNS_DOMAIN", "example.com").strip(".")
tid = random.randint(0, 65535)
flags = 0x0100
header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
qname = b"".join(bytes([len(label)]) + label.encode() for label in domain.split(".")) + b"\\x00"
question = qname + struct.pack("!HH", 1, 1)
packet = header + question

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.2)
try:
    sock.sendto(packet, ("127.0.0.1", 53))
except Exception:
    pass
finally:
    sock.close()
PY

echo '[events] capability: mount syscall path (CAP_SYS_ADMIN check)'
sudo mkdir -p "${CAP_MOUNT_PATH}"
sudo mount -t tmpfs tmpfs "${CAP_MOUNT_PATH}" >/dev/null 2>&1 || true
sudo umount "${CAP_MOUNT_PATH}" >/dev/null 2>&1 || true
sudo rmdir "${CAP_MOUNT_PATH}" >/dev/null 2>&1 || true

echo '[events] done'
EOF
