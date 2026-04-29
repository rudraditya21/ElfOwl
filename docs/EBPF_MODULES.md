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

## TLS Module

- **C module:** `pkg/ebpf/programs/tls.c`
- **Go monitor:** `pkg/ebpf/tls_monitor.go`
- **Event type:** `tls_client_hello`
- **Enriched context:** `TLSContext` (`pkg/enrichment/types.go`)
- **Fields populated:**
  - `ja3_fingerprint` — MD5 of the JA3 string
  - `ja3_string` — `version,ciphers,extensions,curves,point_formats`
  - `tls_version` — legacy_version from ClientHello (e.g. `771` = TLS 1.2)
  - `sni` — server name from the `server_name` extension (0x0000)
  - `ciphers` — cipher suite list (GREASE values filtered)
  - `extensions` — extension type list (GREASE values filtered)
  - `curves` — supported groups from extension 0x000a
  - `point_formats` — EC point formats from extension 0x000b
  - `cert_sha256` — SHA-256 of the leaf certificate DER (colon-separated)
  - `cert_issuer` — issuer Common Name of the leaf certificate
  - `cert_expiry` — Unix timestamp of certificate NotAfter

**Notes:** The eBPF program hooks `sys_enter_write`, `sys_enter_sendto`, and
`sys_enter_writev`. It validates TLS record version (`0x0301–0x0304`) and
handshake type (`0x01`) in-kernel before copying up to 1024 bytes of
ClientHello payload via a per-CPU scratch map (avoids BPF stack overflow).
JA3 parsing and SNI extraction happen in userspace. `cert_sha256` is obtained
by an active TLS probe to `host:443` after SNI is known; results are cached
per-SNI for 10 minutes with singleflight to prevent duplicate dials.

---

## Shared Notes

- All monitors wrap raw events into `EnrichedEvent` with timestamps.
- Kubernetes metadata (pod/namespace/service account, policies) is added by the
  enrichment pipeline, not the eBPF modules.
- Evidence signing/encryption is applied later in the pipeline.
