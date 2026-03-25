# eBPF Modules to Go Monitors Mapping

This document maps each C eBPF program in `pkg/ebpf/programs/` to its Go monitor
and the enrichment fields it populates.

---

## Process Module

- **C module:** `pkg/ebpf/programs/process.c`
- **Go monitor:** `pkg/ebpf/process_monitor.go`
- **Event type:** `process_execution`
- **Enriched context:** `ProcessContext` (`pkg/enrichment/types.go`)
- **Fields populated:**
  - `pid` (ProcessEvent.PID)
  - `uid` (ProcessEvent.UID)
  - `gid` (ProcessEvent.GID)
  - `command` (from `ProcessEvent.Argv` or `Filename`)
  - `arguments` (best-effort from `ProcessEvent.Argv`)
  - `filename` (ProcessEvent.Filename)
  - `container_id` (via cgroup extraction in enrichment pipeline)

**Notes:** Captures execve/execveat tracepoints. Capabilities are captured in the
raw event (`ProcessEvent.Capabilities`) but are not directly surfaced in
`ProcessContext` today.

---

## Network Module

- **C module:** `pkg/ebpf/programs/network.c`
- **Go monitor:** `pkg/ebpf/network_monitor.go`
- **Event type:** `network_connection`
- **Enriched context:** `NetworkContext` (`pkg/enrichment/types.go`)
- **Fields populated:**
  - `source_ip` (IPv4/IPv6 from `NetworkEvent`)
  - `destination_ip` (IPv4/IPv6 from `NetworkEvent`)
  - `source_port` (`NetworkEvent.SPort`)
  - `destination_port` (`NetworkEvent.DPort`)
  - `protocol` (tcp/udp)
  - `direction` (inbound/outbound/unknown from `NetworkEvent.Direction`)
  - `connection_state` (TCP state name from `NetworkEvent.State`)
  - `network_namespace_id` (`NetworkEvent.NetNS`)

**Notes:** Emits from TCP connect/state tracepoints and UDP sendto. Ingress/
Egress restriction fields are populated by Kubernetes network policy enrichment,
not by the eBPF program.

---

## File Module

- **C module:** `pkg/ebpf/programs/file.c`
- **Go monitor:** `pkg/ebpf/file_monitor.go`
- **Event type:** `file_access`
- **Enriched context:** `FileContext` (`pkg/enrichment/types.go`)
- **Fields populated:**
  - `path` (from `FileEvent.Filename` when available)
  - `operation` (read/write/chmod/unlink)
  - `pid` (`FileEvent.PID`)
  - `mode` (`FileEvent.Mode`)
  - `fd` (`FileEvent.FD`)

**Notes:** For write/pwrite operations, only `fd` is populated because no path
is available at the syscall entry tracepoint.

---

## Capability Module

- **C module:** `pkg/ebpf/programs/capability.c`
- **Go monitor:** `pkg/ebpf/capability_monitor.go`
- **Event type:** `capability_usage`
- **Enriched context:** `CapabilityContext` (`pkg/enrichment/types.go`)
- **Fields populated:**
  - `name` (capability name)
  - `allowed` (derived from check type)
  - `pid` (`CapabilityEvent.PID`)
  - `syscall_id` (`CapabilityEvent.SyscallID`)

**Notes:** The module filters to high-risk capabilities and tracks the last
syscall id per PID using `raw_syscalls/sys_enter`.

---

## DNS Module

- **C module:** `pkg/ebpf/programs/dns.c`
- **Go monitor:** `pkg/ebpf/dns_monitor.go`
- **Event type:** `dns_query`
- **Enriched context:** `DNSContext` (`pkg/enrichment/types.go`)
- **Fields populated:**
  - `query_name` (`DNSEvent.QueryName`)
  - `query_type` (`DNSEvent.QueryType`, mapped to RFC name)
  - `response_code` (`DNSEvent.ResponseCode`)
  - `query_allowed` (`DNSEvent.QueryAllowed`)

**Notes:** The DNS event also includes server family and address in the raw
`DNSEvent`, which is logged by the monitor but not currently stored in
`DNSContext`.

---

## Shared Notes

- All monitors wrap raw events into `EnrichedEvent` with timestamps.
- Kubernetes metadata (pod/namespace/service account, policies) is added by the
  enrichment pipeline, not the eBPF modules.
- Evidence signing/encryption is applied later in the pipeline.
