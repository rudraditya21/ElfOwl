// ANCHOR: Network Monitor eBPF Program - Dec 27, 2025
// Kernel-native network connection monitoring
// Captures socket connections for CIS 4.6 controls

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/socket.h>
#include <uapi/linux/tcp.h>
#include <linux/bpf.h>

#define NET_DIR_UNKNOWN 0
#define NET_DIR_OUTBOUND 1
#define NET_DIR_INBOUND 2

// Event structure matching enrichment.NetworkConnection
struct network_event {
    unsigned long cgroup_id;
    unsigned int pid;
    unsigned int netns;
    unsigned int saddr;         // IPv4 source (host byte order)
    unsigned int daddr;         // IPv4 dest (host byte order)
    unsigned short family;      // AF_INET or AF_INET6
    unsigned short sport;       // Source port (host byte order)
    unsigned short dport;       // Destination port (host byte order)
    unsigned char protocol;     // IPPROTO_TCP or IPPROTO_UDP
    unsigned char direction;    // 1=outbound, 2=inbound
    unsigned char state;        // TCP state transition (newstate)
    unsigned char saddr_v6[16];
    unsigned char daddr_v6[16];
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(network_events);

static __always_inline unsigned short net_ntohs(unsigned short val) {
    return (val >> 8) | (val << 8);
}

static __always_inline int read_sockaddr(void *addr, unsigned short *port, unsigned int *daddr, unsigned char daddr_v6[16], unsigned short *family) {
    struct sockaddr sa = {};
    if (addr == 0) {
        return 0;
    }

    if (bpf_probe_read_user(&sa, sizeof(sa), addr) < 0) {
        return 0;
    }

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_user(&sin, sizeof(sin), addr) < 0) {
            return 0;
        }
        *family = AF_INET;
        *port = net_ntohs(sin.sin_port);
        *daddr = 0;
        __builtin_memset(daddr_v6, 0, 16);
        bpf_probe_read_user(daddr, sizeof(__u32), &sin.sin_addr);
        return AF_INET;
    }

    if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_user(&sin6, sizeof(sin6), addr) < 0) {
            return 0;
        }
        *family = AF_INET6;
        *port = net_ntohs(sin6.sin6_port);
        *daddr = 0;
        bpf_probe_read_user(daddr_v6, 16, &sin6.sin6_addr);
        return AF_INET6;
    }

    return 0;
}

// ANCHOR: Network state/ipv6 capture - Feature: tcp+udp coverage - Mar 24, 2026
// Uses inet_sock_set_state for TCP state transitions and sys_enter_sendto for UDP sends.
TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    struct network_event evt = {};

    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.protocol = args->protocol;
    evt.family = args->family;
    evt.sport = args->sport;
    evt.dport = args->dport;
    evt.state = args->newstate;
    evt.direction = NET_DIR_UNKNOWN;
    evt.netns = 0; // TODO: populate netns via CO-RE task_struct access.

    if (args->family == AF_INET6) {
        bpf_probe_read_kernel(&evt.saddr_v6, sizeof(evt.saddr_v6), args->saddr_v6);
        bpf_probe_read_kernel(&evt.daddr_v6, sizeof(evt.daddr_v6), args->daddr_v6);
    } else {
        evt.saddr = *(__u32 *)args->saddr;
        evt.daddr = *(__u32 *)args->daddr;
    }

    if (args->newstate == TCP_SYN_SENT) {
        evt.direction = NET_DIR_OUTBOUND;
    } else if (args->newstate == TCP_SYN_RECV) {
        evt.direction = NET_DIR_INBOUND;
    } else if (args->oldstate == TCP_SYN_SENT && args->newstate == TCP_ESTABLISHED) {
        evt.direction = NET_DIR_OUTBOUND;
    } else if (args->oldstate == TCP_SYN_RECV && args->newstate == TCP_ESTABLISHED) {
        evt.direction = NET_DIR_INBOUND;
    }

    network_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct network_event evt = {};
    unsigned short port = 0;
    unsigned short family = 0;

    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.protocol = IPPROTO_UDP;
    evt.direction = NET_DIR_OUTBOUND;
    evt.state = 0;
    evt.netns = 0; // TODO: populate netns via CO-RE task_struct access.

    if (!read_sockaddr((void *)args->addr, &port, &evt.daddr, evt.daddr_v6, &family)) {
        return 0;
    }

    evt.family = family;
    evt.dport = port;

    network_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
