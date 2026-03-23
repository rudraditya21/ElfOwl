# VM Test Helper Scripts

Linux-only testing helpers using Multipass.

## Recommended Flow

1. `scripts/setup-vm.sh`
2. `scripts/start-vm.sh`
3. `scripts/setup-k8s-vm.sh`
4. `scripts/test-ebpf-kernel.sh --sync --pull`
5. `scripts/test-events.sh --sync --kernel`
6. Live pipeline check: `scripts/test-live-events.sh --sync --rebuild`
7. `scripts/check-state.sh`
8. `scripts/check-logs.sh --type startup`

## Scripts

- `setup-vm.sh`: create/provision VM, install base packages + Go, sync source into VM.
- `setup-k8s-vm.sh`: install/ensure `k3s` API server in VM and write kubeconfig at `/home/ubuntu/.kube/config` by default.
- `sync-vm-src.sh`: copy current repo snapshot into VM project directory.
- `start-vm.sh`: start VM and confirm source availability.
- `vm-exec.sh`: execute arbitrary command in VM (defaults to project dir).
- `build-ebpf-vm.sh`: compile all `pkg/ebpf/programs/*.c` inside VM and validate ELF artifacts (`--pull` copies them back locally).
- `test-ebpf-kernel.sh`: run VM unit tests + root kernel integration tests for process/network/file/capability/DNS event capture, with pass/fail matrix.
- `test-events.sh`: run event-path tests (`pkg/ebpf`, `pkg/rules` integration, and Kubernetes compliance event builders in `pkg/agent`) and print a pass/fail matrix (`--kernel` also runs root kernel eBPF integration checks).
- `start-agent.sh`: build/start agent in VM and fail fast with logs if startup fails.
- `stop-agent.sh`: stop running agent process.
- `generate-events.sh`: trigger concrete process/network/dns/file/capability activity in VM for live log validation.
- `check-event-values.sh`: print per-event counts and latest event lines with captured values from agent log.
- `test-live-events.sh`: one-shot live test (`setup-k8s` optional, restart agent, generate events, show state/summary/value samples).
- `check-state.sh`: process state + health + metrics + recent errors.
- `check-logs.sh`: filtered logs by category.
- `event-summary.sh`: count event/violation log lines (use debug level for event-sent counts).

## Important Notes

- The agent requires Kubernetes client access at startup. Use `scripts/setup-k8s-vm.sh` and run `start-agent.sh --kubeconfig /home/ubuntu/.kube/config`.
- `test-events.sh --kernel` is the primary automated eBPF verification path.
- `test-live-events.sh` is the quickest way to validate live event capture and inspect actual values in logs.
