// ANCHOR: DNS Monitor eBPF Program - Dec 27, 2025
// Kernel-native DNS query monitoring
// Captures DNS requests for CIS 4.6.4 controls (DNS exfiltration detection)

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <linux/bpf.h>

// Event structure matching enrichment.DNSQuery
struct dns_event {
    unsigned int pid;
    unsigned short query_type;  // A=1, AAAA=28, MX=15, TXT=16, etc.
    unsigned char response_code; // 0=NOERROR, 1=FORMERR, 2=SERVFAIL, etc.
    unsigned char query_allowed; // 1=allowed, 0=suspicious/blocked
    unsigned long cgroup_id;
    char query_name[256];        // Domain name being queried
    char server[16];             // DNS server IP (in IPv4 format)
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(dns_events);

// Tracepoint: trace_dns_query via UDP port 53 monitoring
// Fires when DNS queries are sent to port 53
TRACEPOINT_PROBE(udp, udp_sendmsg) {
    struct dns_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.query_allowed = 1;  // Default: allow (policy evaluation in userspace)
    evt.cgroup_id = bpf_get_current_cgroup_id();

    // ANCHOR: DNS tracepoint extraction - Feature: cgroup/server/port53 - Mar 23, 2026
    // Filters UDP traffic to port 53 and captures server address for CIS 4.6.4 signals.
    if (args->dport != 53 && args->sport != 53) {
        return 0;
    }

    // Best-effort IPv4 server capture; IPv6 parsing will be added in a later phase.
    bpf_probe_read_kernel(&evt.server, sizeof(__u32), &args->daddr);

    // TODO (Phase 3): Parse DNS payload to extract query name/type/rcode.

    dns_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
