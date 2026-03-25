# ELF OWL Linux Setup (Existing Linux Machine)

This guide sets up and runs `elf-owl` directly on a Linux host (not Multipass).
It assumes you already have a working Linux machine and `sudo` access.

## 1) Prerequisites

- Linux kernel with eBPF/tracepoint support (modern distro kernel is usually fine)
- `sudo` access
- Internet access (for Go modules and optional k3s install)

Quick checks:

```bash
uname -a
id
```

### CO-RE prerequisites

CO-RE builds require kernel BTF and bpftool. Verify:

```bash
ls -l /sys/kernel/btf/vmlinux
which bpftool
```

If needed, generate `pkg/ebpf/programs/vmlinux.h` with:

```bash
scripts/generate-vmlinux.sh
```

## 2) Install Dependencies (idempotent)

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
  git curl ca-certificates make gcc clang llvm jq \
  libbpf-dev linux-libc-dev bpftool dnsutils python3
```

### Fedora/RHEL/CentOS Stream

```bash
sudo dnf install -y \
  git curl ca-certificates make gcc clang llvm jq \
  libbpf-devel kernel-headers bpftool bind-utils python3
```

## 3) Install Go 1.23.x (if needed)

`go.mod` requires Go `1.23.x`.

```bash
go version || true
```

If Go is missing or older than 1.23, install:

```bash
cd /tmp
curl -fsSLO https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
rm -f go1.23.0.linux-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
export PATH=/usr/local/go/bin:$PATH
go version
```

## 4) Clone and Build

```bash
git clone <YOUR_REPO_URL> owl-agent
cd owl-agent
```

Build eBPF object files:

```bash
cd pkg/ebpf/programs
make clean
make
cd ../../..
```

Build agent binary:

```bash
go build -mod=mod -o elf-owl ./cmd/elf-owl
```

## 5) Real Kubernetes API Server for Testing

`elf-owl` requires Kubernetes API access at startup.

If you already have a real cluster, just point `KUBECONFIG` to it and skip to Step 6.
If you want a local test-only real API server, use single-node k3s:

### 5.1 Install k3s (test-only real API server)

```bash
curl -sfL https://get.k3s.io | sh -
sudo systemctl enable --now k3s
sudo systemctl is-active k3s
sudo k3s kubectl get nodes -o wide
```

Create kubeconfig for your user:

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown "$USER:$USER" ~/.kube/config
chmod 600 ~/.kube/config
kubectl --kubeconfig ~/.kube/config get nodes -o wide
```

### 5.2 Seed minimal Kubernetes objects (for testing only)

This is optional but useful to confirm API access and watcher behavior:

```bash
kubectl --kubeconfig ~/.kube/config create ns owl-test || true
kubectl --kubeconfig ~/.kube/config -n owl-test run owl-test-nginx --image=nginx:stable --restart=Always || true
kubectl --kubeconfig ~/.kube/config -n owl-test get pods -o wide
```

### 5.3 Optional cleanup after testing

```bash
kubectl --kubeconfig ~/.kube/config delete ns owl-test --ignore-not-found=true
sudo /usr/local/bin/k3s-uninstall.sh || true
```

## 6) Start Agent (debug)

Prepare runtime directories:

```bash
sudo mkdir -p /var/log/elf-owl /var/run/elf-owl
sudo truncate -s 0 /var/log/elf-owl/agent.log
```

Run in background:

```bash
cd /path/to/owl-agent
sudo env \
  KUBECONFIG=/home/$USER/.kube/config \
  OWL_K8S_IN_CLUSTER=false \
  OWL_LOG_LEVEL=debug \
  nohup ./elf-owl >/var/log/elf-owl/agent.log 2>&1 < /dev/null &
echo $! | sudo tee /var/run/elf-owl/agent.pid
```

## 7) Validate Agent Health

```bash
curl -sf http://127.0.0.1:9091/health
curl -sf http://127.0.0.1:9090/metrics | grep '^elf_owl_' | head
sudo tail -n 120 /var/log/elf-owl/agent.log
```

## 8) Trigger All 5 Event Types

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

Watch events:

```bash
sudo tail -F -n 200 /var/log/elf-owl/agent.log \
| grep --line-buffered -E 'process event sent|network event sent|dns event sent|file event sent|capability event sent'
```

## 9) Stop Agent

```bash
if sudo test -f /var/run/elf-owl/agent.pid; then
  sudo kill "$(sudo cat /var/run/elf-owl/agent.pid)" || true
  sudo rm -f /var/run/elf-owl/agent.pid
fi
sudo pkill -x elf-owl || true
```

## Notes

- For local testing, `/var/log/elf-owl/agent.log` is the primary source of truth.
- If startup fails with Kubernetes config errors, verify:
  - `KUBECONFIG` path exists
  - `OWL_K8S_IN_CLUSTER=false` is set
  - k3s API server is active (`sudo systemctl is-active k3s`)
