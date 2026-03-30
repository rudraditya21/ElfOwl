# ELF OWL Cheatsheet

Quick reference for VM setup, k3s, agent control, log inspection, and test scripts.

## 1) Defaults and Paths

```text
VM name:                elf-owl-dev
VM project dir:         /home/ubuntu/work/owl-agent
Kubeconfig in VM:       /home/ubuntu/.kube/config
Agent log in VM:        /var/log/elf-owl/agent.log
Agent PID file in VM:   /var/run/elf-owl/agent.pid
```

## 2) Full Manual Validation Flow (Your Exact 2-Terminal Flow)

### 2.1 Host: start agent in debug mode

```bash
scripts/setup-vm.sh --name elf-owl-dev --cpus 2 --memory 6G --disk 20G
scripts/setup-k8s-vm.sh --name elf-owl-dev --kubeconfig /home/ubuntu/.kube/config
scripts/build-ebpf-vm.sh --name elf-owl-dev --sync --pull


scripts/start-agent.sh --name elf-owl-dev --log-level debug --kubeconfig /home/ubuntu/.kube/config
```

### 2.2 Terminal A: VM shell + live event watch

```bash
multipass shell elf-owl-dev
```

```bash
sudo tail -F -n 150 /var/log/elf-owl/agent.log | grep --line-buffered -E 'process event sent|network event sent|dns event sent|file event sent|capability event sent'
```

### 2.3 Terminal B: VM shell + event triggers

```bash
multipass shell elf-owl-dev
```

```bash
# process
/bin/sh -lc 'echo process-test >/dev/null'
/usr/bin/id >/dev/null

# file
echo "file-test-$(date +%s)" > /tmp/elf-owl-test.txt
cat /tmp/elf-owl-test.txt >/dev/null

# network
timeout 3 bash -lc 'cat </dev/null >/dev/tcp/1.1.1.1/80' || true

# dns
python3 - <<'PY'
import socket, struct, random
tid=random.randint(0,65535)
hdr=struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
q=b"\x07example\x03com\x00"+struct.pack("!HH",1,1)
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.sendto(hdr+q, ("127.0.0.1",53))
sock.close()
PY

# capability
sudo mkdir -p /tmp/elf-owl-cap-test
sudo mount -t tmpfs tmpfs /tmp/elf-owl-cap-test || true
sudo umount /tmp/elf-owl-cap-test || true
sudo rmdir /tmp/elf-owl-cap-test || true
```

## 3) Timestamped Live Event Streams (Inside VM)

`Ctrl + C` to stop any stream.

### Process only
```bash
sudo tail -F -n 200 /var/log/elf-owl/agent.log \
| awk '/process event sent/ { ts=$1; sub(/^.*process event sent[[:space:]]+/, "", $0); print ts "\t" $0; fflush(); }' \
| jq -Rr 'split("\t") as $p | ($p[0] // "-") as $ts | ($p[1] // "" | fromjson?) as $j | select($j) | "\($ts) PROCESS pid=\($j.pid // "-") uid=\($j.uid // "-") gid=\($j.gid // "-") file=\($j.filename // "-") cmd=\($j.command // "-")"'
```

### Network only
```bash
sudo tail -F -n 200 /var/log/elf-owl/agent.log \
| awk '/network event sent/ { ts=$1; sub(/^.*network event sent[[:space:]]+/, "", $0); print ts "\t" $0; fflush(); }' \
| jq -Rr 'split("\t") as $p | ($p[0] // "-") as $ts | ($p[1] // "" | fromjson?) as $j | select($j) | "\($ts) NETWORK pid=\($j.pid // "-") \($j.src // "-"):\($j.src_port // "-") -> \($j.dest // "-"):\($j.dest_port // "-") proto=\($j.protocol // "-")"'
```

### DNS only
```bash
sudo tail -F -n 200 /var/log/elf-owl/agent.log \
| awk '/dns event sent/ { ts=$1; sub(/^.*dns event sent[[:space:]]+/, "", $0); print ts "\t" $0; fflush(); }' \
| jq -Rr 'split("\t") as $p | ($p[0] // "-") as $ts | ($p[1] // "" | fromjson?) as $j | select($j) | "\($ts) DNS pid=\($j.pid // "-") domain=\($j.domain // "-") type=\($j.query_type // "-") rcode=\($j.response_code // "-") allowed=\($j.allowed // "-")"'
```

### File only
```bash
sudo tail -F -n 200 /var/log/elf-owl/agent.log \
| awk '/file event sent/ { ts=$1; sub(/^.*file event sent[[:space:]]+/, "", $0); print ts "\t" $0; fflush(); }' \
| jq -Rr 'split("\t") as $p | ($p[0] // "-") as $ts | ($p[1] // "" | fromjson?) as $j | select($j) | "\($ts) FILE pid=\($j.pid // "-") op=\($j.operation // "-") path=\($j.file // "-") flags=\($j.flags // "-")"'
```

### Capability only
```bash
sudo tail -F -n 200 /var/log/elf-owl/agent.log \
| awk '/capability event sent/ { ts=$1; sub(/^.*capability event sent[[:space:]]+/, "", $0); print ts "\t" $0; fflush(); }' \
| jq -Rr 'split("\t") as $p | ($p[0] // "-") as $ts | ($p[1] // "" | fromjson?) as $j | select($j) | "\($ts) CAP pid=\($j.pid // "-") cap=\($j.capability // "-") check=\($j.check_type // "-") syscall=\($j.syscall // "-")"'
```

## 4) Kubernetes Status (Inside VM Shell)

```bash
sudo systemctl is-active k3s
sudo systemctl status k3s --no-pager -l
sudo k3s kubectl get nodes -o wide
sudo k3s kubectl get ns
sudo k3s kubectl get pods -A -o wide
```

## 5) Script Usage and Help

### Show help for every script

```bash
for s in scripts/*.sh; do
  echo "===== $s ====="
  "$s" --help || true
  echo
done
```

### Script catalog

```text
scripts/setup-vm.sh
  Purpose: create/provision VM, install base deps + Go, sync repository into VM.
  Common:  scripts/setup-vm.sh --name elf-owl-dev --cpus 4 --memory 8G --disk 30G

scripts/start-vm.sh
  Purpose: start VM and verify source path exists.
  Common:  scripts/start-vm.sh --name elf-owl-dev

scripts/sync-vm-src.sh
  Purpose: sync local repo snapshot to VM project dir.
  Common:  scripts/sync-vm-src.sh --name elf-owl-dev

scripts/vm-exec.sh
  Purpose: run arbitrary command inside VM.
  Common:  scripts/vm-exec.sh --name elf-owl-dev --no-cd -- bash -lc 'uname -a'

scripts/setup-k8s-vm.sh
  Purpose: install/ensure k3s and place kubeconfig inside VM.
  Common:  scripts/setup-k8s-vm.sh --name elf-owl-dev --kubeconfig /home/ubuntu/.kube/config

scripts/build-ebpf-vm.sh
  Purpose: compile eBPF C programs in VM; optionally pull .o files to host.
  Common:  scripts/build-ebpf-vm.sh --name elf-owl-dev --sync --pull

scripts/test-ebpf-kernel.sh
  Purpose: run eBPF unit tests + root kernel integration event matrix.
  Common:  scripts/test-ebpf-kernel.sh --name elf-owl-dev --sync --pull

scripts/test-events.sh
  Purpose: run event-path tests (pkg/ebpf, rules integration, compliance event builders).
  Common:  scripts/test-events.sh --name elf-owl-dev --sync --kernel
  Extra:   add --full for go test ./...

scripts/start-agent.sh
  Purpose: build/start elf-owl inside VM; supports kubeconfig override.
  Common:  scripts/start-agent.sh --name elf-owl-dev --log-level debug --kubeconfig /home/ubuntu/.kube/config
  Common:  scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug --kubeconfig /home/ubuntu/.kube/config
  No-K8s:  scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug --no-k8s

scripts/stop-agent.sh
  Purpose: stop tracked and orphan elf-owl process in VM.
  Common:  scripts/stop-agent.sh --name elf-owl-dev

scripts/check-state.sh
  Purpose: process status, /health, key /metrics, and recent errors.
  Common:  scripts/check-state.sh --name elf-owl-dev

scripts/check-logs.sh
  Purpose: filtered log views by type.
  Common:  scripts/check-logs.sh --name elf-owl-dev --type startup --lines 120
  Types:   startup, monitors, events, violations, push, errors, all

scripts/event-summary.sh
  Purpose: count process/network/dns/file/capability events and violations from logs.
  Common:  scripts/event-summary.sh --name elf-owl-dev

scripts/check-event-values.sh
  Purpose: sample latest value-rich lines for each event type.
  Common:  scripts/check-event-values.sh --name elf-owl-dev --lines 10

scripts/generate-events.sh
  Purpose: trigger process/file/network/dns/capability activity in VM.
  Common:  scripts/generate-events.sh --name elf-owl-dev

scripts/test-live-events.sh
  Purpose: one-shot live flow (optional k8s setup, restart agent, generate/check events).
  Common:  scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild --sample-lines 5
  No-K8s:  scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild --sample-lines 5 --without-k8s
```

## 6) Daily Operations

```bash
# Stop agent, clear log, start clean in debug
scripts/stop-agent.sh --name elf-owl-dev || true
scripts/vm-exec.sh --name elf-owl-dev --no-cd -- bash -lc 'sudo truncate -s 0 /var/log/elf-owl/agent.log || true'
scripts/start-agent.sh --name elf-owl-dev --log-level debug --kubeconfig /home/ubuntu/.kube/config

# Quick state checks
scripts/check-state.sh --name elf-owl-dev
scripts/event-summary.sh --name elf-owl-dev
scripts/check-logs.sh --name elf-owl-dev --type events --lines 300
scripts/check-event-values.sh --name elf-owl-dev --lines 10
```


## Delete instances

```sh
# Stop a specific VM
multipass stop elf-owl-dev

# Delete a specific VM
multipass delete elf-owl-dev

# Purge deleted VMs permanently
multipass purge

# Delete all VMs at once
multipass delete --all
multipass purge
```
