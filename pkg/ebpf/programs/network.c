// ANCHOR: Network Monitor eBPF Program - Dec 27, 2025
// Kernel-native network connection monitoring
// Captures socket connections for CIS 4.6 controls

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <linux/bpf.h>

// Event structure matching enrichment.NetworkConnection
struct network_event {
    unsigned int pid;
    unsigned short family;      // AF_INET or AF_INET6
    unsigned short sport;       // Source port (network byte order)
    unsigned short dport;       // Destination port (network byte order)
    unsigned int saddr;         // Source IPv4 or first 4 bytes of IPv6
    unsigned int daddr;         // Destination IPv4 or first 4 bytes of IPv6
    unsigned char protocol;     // IPPROTO_TCP or IPPROTO_UDP
    unsigned long cgroup_id;
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(network_events);

// Tracepoint: trace_tcp_connect (TCP connection establishment)
// Fires when a TCP connection is established
TRACEPOINT_PROBE(tcp, tcp_connect) {
    struct network_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.protocol = IPPROTO_TCP;
    evt.cgroup_id = bpf_get_current_cgroup_id();

    // ANCHOR: TCP connect extraction - Feature: addr/ports/cgroup - Mar 23, 2026
    // Captures IPv4 endpoints and port data from tracepoint payload for CIS 4.6 signals.
    evt.family = args->family;
    evt.saddr = args->saddr;
    evt.daddr = args->daddr;
    evt.sport = args->sport;
    evt.dport = args->dport;

    network_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
