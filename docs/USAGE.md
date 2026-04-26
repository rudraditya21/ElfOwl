# elf-owl Usage Guide

## Overview

**elf-owl** is a Kubernetes-native security monitoring agent that captures and enriches kernel-level events for compliance, threat detection, and forensics. It uses eBPF (Extended Berkeley Packet Filter) to monitor system activity without requiring changes to your applications or kernel modules.

## What elf-owl Monitors

elf-owl captures six categories of security-relevant events:

### 1. Process Execution Events
Monitors when processes are executed on the node, capturing:
- **Process name and arguments** - The command and its parameters
- **Process ID (PID)** - Unique identifier for the running process
- **User context** - UID/GID of the process owner
- **Parent process** - The process that spawned this one
- **Execution path** - Full path to the executable

**Use cases:**
- Detect unauthorized command execution
- Track privilege escalation attempts
- Monitor application startup patterns
- Compliance audit trails

**Example enriched event:**
```json
{
  "event_type": "process_execution",
  "process": {
    "pid": 12345,
    "name": "curl",
    "arguments": ["curl", "https://external-api.com/data"],
    "uid": 1000,
    "gid": 1000,
    "parent_pid": 12340
  },
  "kubernetes": {
    "pod_name": "my-app-56d4f9c5b5-abc123",
    "namespace": "production",
    "container_name": "app"
  }
}
```

### 2. Network Connection Events
Monitors when processes establish network connections, capturing:
- **Source and destination IPs** - IPv4 or IPv6 addresses
- **Source and destination ports** - TCP or UDP ports
- **Protocol type** - TCP, UDP, or ICMP
- **Connection direction** - Outbound vs inbound
- **Process context** - Which process opened the connection

**Use cases:**
- Detect data exfiltration attempts
- Identify command-and-control (C2) communications
- Monitor unauthorized external connections
- Compliance monitoring for data residency

**Example enriched event:**
```json
{
  "event_type": "network_connection",
  "network": {
    "source_ip": "10.0.1.100",
    "source_port": 54321,
    "destination_ip": "203.0.113.50",
    "destination_port": 443,
    "protocol": "tcp",
    "direction": "outbound"
  },
  "process": {
    "pid": 12345,
    "name": "curl"
  },
  "kubernetes": {
    "pod_name": "my-app-56d4f9c5b5-abc123",
    "namespace": "production"
  }
}
```

### 3. DNS Query Events
Monitors DNS queries performed by processes, capturing:
- **Query domain** - The domain being looked up
- **Query type** - A, AAAA, MX, NS, etc.
- **Query result** - Success or failure
- **Response code** - NOERROR, NXDOMAIN, SERVFAIL, etc.
- **Process context** - Which process made the query

**Use cases:**
- Detect malware domain lookups
- Monitor DNS tunneling attempts
- Ensure compliance with allowed domain policies
- Forensic investigation of suspicious activities

**Example enriched event:**
```json
{
  "event_type": "dns_query",
  "dns": {
    "query_domain": "example-malware.com",
    "query_type": "A",
    "response_code": "NXDOMAIN",
    "query_allowed": false
  },
  "process": {
    "pid": 12345,
    "name": "curl"
  },
  "kubernetes": {
    "pod_name": "my-app-56d4f9c5b5-abc123",
    "namespace": "production"
  }
}
```

### 4. File Access Events
Monitors when processes access files on the filesystem, capturing:
- **File path** - The file being accessed
- **Operation type** - Read, write, execute, open, etc.
- **Process context** - Which process accessed the file
- **User context** - UID/GID of the accessing process

**Use cases:**
- Detect unauthorized file reads or writes
- Monitor access to sensitive configuration files
- Compliance tracking of who accesses what data
- Forensic investigation of system changes

**Example enriched event:**
```json
{
  "event_type": "file_access",
  "file": {
    "path": "/etc/shadow",
    "operation": "read",
    "uid": 1000,
    "gid": 1000
  },
  "process": {
    "pid": 12345,
    "name": "cat"
  },
  "kubernetes": {
    "pod_name": "my-app-56d4f9c5b5-abc123",
    "namespace": "production"
  }
}
```

### 5. TLS ClientHello Events
Monitors outbound TLS connections, capturing:
- **JA3 fingerprint** - MD5 hash identifying the TLS client implementation
- **SNI** - Server Name Indication (target hostname)
- **TLS version** - Negotiated protocol version
- **Cipher suites** - Client-offered cipher list
- **Certificate SHA-256** - Leaf certificate fingerprint (via active probe)
- **Certificate issuer** - CA that issued the server certificate

**Use cases:**
- Detect unusual TLS client fingerprints (malware, custom tools)
- Identify connections to servers with untrusted or expired certificates
- Monitor which external hosts workloads connect to via SNI
- Forensic attribution of TLS flows to specific processes/pods

**Example enriched event:**
```json
{
  "event_type": "tls_client_hello",
  "tls": {
    "ja3_fingerprint": "0149f47eabf9a20d0893e2a44e5a6323",
    "ja3_string": "771,4866-4867-4865,...,29-23-24,0",
    "tls_version": "771",
    "sni": "api.example.com",
    "cert_sha256": "1b:e0:11:f7:25:35:b4:...",
    "cert_issuer": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "cert_expiry": 1767225600
  },
  "kubernetes": {
    "pod_name": "my-app-56d4f9c5b5-abc123",
    "namespace": "production"
  }
}
```

### 6. Linux Capability Usage Events
Monitors when processes use Linux capabilities, capturing:
- **Capability name** - The specific Linux capability (e.g., CAP_NET_RAW)
- **Capability ID** - Numeric ID of the capability
- **Operation type** - Check, grant, or usage
- **Result** - Allowed or denied
- **Process context** - Which process attempted the operation

**Use cases:**
- Detect privilege escalation attempts
- Monitor capability abuse by containers
- Compliance verification of minimal privilege principles
- Forensic analysis of security violations

**Example enriched event:**
```json
{
  "event_type": "capability_usage",
  "capability": {
    "name": "CAP_NET_RAW",
    "id": 13,
    "operation": "check",
    "denied": true
  },
  "process": {
    "pid": 12345,
    "name": "nmap"
  },
  "kubernetes": {
    "pod_name": "my-app-56d4f9c5b5-abc123",
    "namespace": "production"
  }
}
```

## Rule Engine & Violations

elf-owl includes a **rule engine** that evaluates enriched events against security policies. Rules can detect:

- **Policy violations** - Activities that violate your security policies
- **Compliance violations** - Activities that violate compliance frameworks (PCI-DSS, HIPAA, CIS Benchmarks)
- **Threat patterns** - Known attack signatures and suspicious behaviors

### How Rules Work

1. **Event enrichment** - Raw kernel event is enhanced with Kubernetes context
2. **Rule evaluation** - Event is checked against all active rules
3. **Violation detection** - If event matches rule conditions, a violation is recorded
4. **Compliance tagging** - Violation is tagged with relevant compliance frameworks

### Rule Sources

elf-owl supports two rule sources:

- **File-based rules (default)**: `config/rules/cis-controls.yaml` contains the full CIS v1.8 ruleset. Configure with `rules.file_path` in `elf-owl.yaml`.
- **ConfigMap rules (opt-in)**: A small starter subset is provided in `deploy/helm/templates/configmap-rules.yaml` and `deploy/kustomize/base/configmap-rules.yaml`. Enable explicitly:
  - Helm: `--set rules.configMap.enabled=true`
  - Kustomize: `kubectl apply -k deploy/kustomize/overlays/with-rules`

The ConfigMap starter set is intentionally small; use it as a template or switch to the full file-based rules for complete CIS coverage.

### Example Rule

```yaml
# Example: Detect root process execution
rules:
  - id: "proc-root-exec"
    name: "Root Process Execution"
    description: "Alert on any process execution with UID 0"
    event_type: "process_execution"
    conditions:
      - field: "process.uid"
        operator: "equals"
        value: 0
    severity: "high"
    cis_controls:
      - "4.1.5"  # CIS Control: Controlled Use of Administrative Privileges
```

## Kubernetes Integration

elf-owl automatically integrates with your Kubernetes cluster to enrich events with context:

### Enrichment Data Added

- **Pod metadata** - Pod name, namespace, labels
- **Service account** - Service account name and associated roles
- **Container information** - Container name, image, registry
- **Network policies** - Applicable NetworkPolicy objects
- **RBAC context** - Role and ClusterRole bindings

### Example Enriched Event with Full K8s Context

```json
{
  "event_type": "process_execution",
  "timestamp": "2025-01-25T10:30:45.123Z",
  "severity": "medium",
  "cis_control": "4.1",
  "process": {
    "pid": 12345,
    "name": "bash",
    "arguments": ["bash", "-c", "curl http://evil.com"],
    "uid": 1000,
    "gid": 1000
  },
  "kubernetes": {
    "cluster_id": "prod-us-east-1",
    "node_name": "worker-01",
    "pod_name": "web-app-56d4f9c5b5-abc123",
    "namespace": "production",
    "pod_labels": {
      "app": "web-app",
      "version": "v1"
    },
    "container_name": "app",
    "container_image": "myregistry.azurecr.io/web-app:v1.2.3",
    "service_account": "web-app-sa",
    "service_account_roles": [
      "web-app-reader"
    ]
  },
  "container": {
    "id": "containerd://abc123def456...",
    "runtime": "containerd"
  }
}
```

## Configuration

### Enabling/Disabling Monitors

elf-owl is controlled via YAML configuration. You can enable or disable specific monitors:

```yaml
agent:
  cluster_id: "prod-us-east-1"
  node_name: "worker-01"

  ebpf:
    enabled: true              # Master switch - enable all monitoring

    # Individual monitor configuration
    process:
      enabled: true            # Monitor process execution
      buffer_size: 8192        # Events to buffer before push
      timeout: 5s              # Batch timeout

    network:
      enabled: true            # Monitor network connections
      buffer_size: 8192
      timeout: 5s

    dns:
      enabled: true            # Monitor DNS queries
      buffer_size: 8192
      timeout: 5s

    file:
      enabled: true            # Monitor file access
      buffer_size: 8192
      timeout: 5s

    capability:
      enabled: true            # Monitor capability usage
      buffer_size: 8192
      timeout: 5s

    tls:
      enabled: true            # Monitor TLS ClientHello / JA3
      buffer_size: 4096
      timeout: 5s
```

### Selective Monitoring

To disable specific monitors while keeping others active:

```yaml
agent:
  ebpf:
    enabled: true

    process:
      enabled: true            # Keep process monitoring

    network:
      enabled: false           # Disable network monitoring

    dns:
      enabled: true            # Keep DNS monitoring

    file:
      enabled: false           # Disable file monitoring

    capability:
      enabled: false           # Disable capability monitoring

    tls:
      enabled: true            # Keep TLS monitoring
```

### Logging Configuration

```yaml
logging:
  level: "info"                # debug, info, warn, error
  format: "json"               # json or text
  output: "stdout"             # stdout or file path
```

### Rule Configuration

```yaml
rules:
  enabled: true
  paths:
    - "/etc/elf-owl/rules/"    # Directory containing rule files

  # Built-in compliance frameworks to enforce
  frameworks:
    - "cis-benchmark"
    - "pci-dss"
    - "hipaa"
```

## Event Export & Compliance

### Current: Owl SaaS Platform

Events are sent to the **Owl compliance platform** for:
- Centralized event storage
- Compliance reporting
- Threat analysis
- Audit trails

Configuration:

```yaml
owl_api:
  enabled: true
  endpoint: "https://api.owl-platform.com"
  cluster_id: "prod-us-east-1"
  auth:
    token: "${OWL_API_TOKEN}"  # Set via environment variable
```

### Future: Multi-Destination Export

Additional export destinations will be supported:

- **File-based export** - JSON/XML to local files or volumes
- **Syslog export** - RFC 3164/5424 syslog format
- **HTTP webhooks** - Send events to external systems
- **Database export** - Store in PostgreSQL, Elasticsearch, etc.
- **Message queues** - Kafka, RabbitMQ, etc.

## Typical Deployment Patterns

### Pattern 1: Full Monitoring (Default)

All monitors enabled, events sent to Owl platform:

```yaml
agent:
  ebpf:
    enabled: true
    process:
      enabled: true
    network:
      enabled: true
    dns:
      enabled: true
    file:
      enabled: true
    capability:
      enabled: true
    tls:
      enabled: true

owl_api:
  enabled: true
  endpoint: "https://api.owl-platform.com"
```

### Pattern 2: Minimal Footprint

Only process and network monitoring for high-throughput environments:

```yaml
agent:
  ebpf:
    enabled: true
    process:
      enabled: true
    network:
      enabled: true
    dns:
      enabled: false
    file:
      enabled: false
    capability:
      enabled: false
```

### Pattern 3: Compliance-Focused

All monitors enabled with strict compliance rules:

```yaml
agent:
  ebpf:
    enabled: true
    process:
      enabled: true
    network:
      enabled: true
    dns:
      enabled: true
    file:
      enabled: true
    capability:
      enabled: true
    tls:
      enabled: true

rules:
  enabled: true
  frameworks:
    - "cis-benchmark"
    - "pci-dss"
```

### Pattern 4: Development/Testing

Limited monitoring, local syslog export:

```yaml
agent:
  ebpf:
    enabled: true
    process:
      enabled: true
    network:
      enabled: false
    dns:
      enabled: false
    file:
      enabled: false
    capability:
      enabled: false

logging:
  level: "debug"
```

## Event Flow

Here's how events flow through elf-owl:

```
1. Kernel Event (via eBPF)
   ↓
2. Raw Event Capture (ProcessMonitor, NetworkMonitor, etc.)
   ↓
3. Event Enrichment (Add K8s context, container info)
   ↓
4. Rule Evaluation (Check against security policies)
   ↓
5. Violation Detection (Record any policy violations)
   ↓
6. Event Buffering (Batch events for efficiency)
   ↓
7. Export (Send to Owl platform or other destinations)
   ↓
8. Compliance Reporting (Available in Owl platform)
```

## Performance Considerations

### Event Volume

Typical event volumes by monitor type (per node per minute):

- **Process execution**: 100-1000 events/min (depends on workload)
- **Network connections**: 500-5000 events/min (depends on traffic)
- **DNS queries**: 100-2000 events/min (depends on application)
- **File access**: 1000-10000 events/min (high overhead, consider disabling)
- **Capability usage**: 100-1000 events/min (usually low)
- **TLS ClientHello**: 50-500 events/min (one per outbound TLS handshake)

### Resource Usage

elf-owl resource consumption:

- **CPU**: 2-5% on typical workloads (minimal eBPF overhead)
- **Memory**: 50-100MB base, grows with buffer size
- **Network**: Minimal bandwidth for event export (gzip compressed)

### Tuning

To reduce resource usage:

```yaml
agent:
  ebpf:
    # Reduce buffer sizes
    process:
      buffer_size: 4096    # Default 8192
      timeout: 10s         # Default 5s

    # Disable expensive monitors
    file:
      enabled: false       # File monitoring is expensive
```

## Troubleshooting

### No Events Captured

1. Check that monitors are enabled:
   ```bash
   kubectl logs -n kube-system deployment/elf-owl | grep "monitor initialized"
   ```

2. Verify configuration was applied:
   ```bash
   kubectl get configmap -n kube-system elf-owl-config -o yaml | grep ebpf
   ```

### High Memory Usage

1. Reduce buffer sizes:
   ```yaml
   agent:
     ebpf:
       process:
         buffer_size: 4096  # Reduce from 8192
   ```

2. Disable expensive monitors (file monitoring):
   ```yaml
   agent:
     ebpf:
       file:
         enabled: false
   ```

### Events Not Reaching Owl Platform

1. Check API connectivity:
   ```bash
   kubectl logs -n kube-system deployment/elf-owl | grep "owl_api"
   ```

2. Verify authentication token:
   ```bash
   kubectl get secret -n kube-system elf-owl-api-token -o yaml
   ```

3. Check network policies:
   ```bash
   kubectl get networkpolicies -A | grep elf-owl
   ```

## Next Steps

- **Installation**: See [INSTALLATION.md](INSTALLATION.md) for deployment steps
- **Configuration**: Customize [elf-owl.yaml](../config/elf-owl.yaml) for your environment
- **Rules**: Create custom rules in `/etc/elf-owl/rules/`
- **Integration**: Connect to your SIEM or compliance platform

## Support

For issues or questions:
- Check logs: `kubectl logs -n kube-system deployment/elf-owl`
- Review configuration: `kubectl describe configmap -n kube-system elf-owl-config`
- Enable debug logging: Set `logging.level: debug` in configuration
