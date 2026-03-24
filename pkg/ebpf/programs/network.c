// ANCHOR: Network Monitor eBPF Program - Dec 27, 2025
// Kernel-native network connection monitoring
// Captures socket connections for CIS 4.6 controls

#include "common.h"

#define NET_DIR_UNKNOWN 0
#define NET_DIR_OUTBOUND 1
#define NET_DIR_INBOUND 2

// Event structure matching enrichment.NetworkConnection
struct network_event {
	__u64 cgroup_id;
	__u32 pid;
	__u32 netns;
	__u32 saddr;       // IPv4 source (host byte order)
	__u32 daddr;       // IPv4 dest (host byte order)
	__u16 family;      // AF_INET or AF_INET6
	__u16 sport;       // Source port (host byte order)
	__u16 dport;       // Destination port (host byte order)
	__u8 protocol;     // IPPROTO_TCP or IPPROTO_UDP
	__u8 direction;    // 1=outbound, 2=inbound
	__u8 state;        // TCP state transition (newstate)
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} network_events SEC(".maps");

#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#endif

#ifndef TCP_SYN_SENT
#define TCP_SYN_SENT 2
#endif

#ifndef TCP_SYN_RECV
#define TCP_SYN_RECV 3
#endif

static __always_inline __u16 net_ntohs(__u16 val) {
	return bpf_ntohs(val);
}

static __always_inline __u32 pack_ipv4(const __u8 addr[4]) {
	return ((__u32)addr[0]) |
	       ((__u32)addr[1] << 8) |
	       ((__u32)addr[2] << 16) |
	       ((__u32)addr[3] << 24);
}

static __always_inline int read_sockaddr(const void *addr, __u16 *port, __u32 *daddr, __u8 daddr_v6[16], __u16 *family) {
	struct sockaddr sa = {};
	if (!addr) {
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
		*daddr = bpf_ntohl(sin.sin_addr.s_addr);
		__builtin_memset(daddr_v6, 0, 16);
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
		bpf_probe_read_user(daddr_v6, sizeof(sin6.sin6_addr.in6_u.u6_addr8), &sin6.sin6_addr.in6_u.u6_addr8);
		return AF_INET6;
	}

	return 0;
}

// ANCHOR: Network state/ipv6 capture - Feature: tcp+udp coverage - Mar 24, 2026
// Uses inet_sock_set_state for TCP state transitions and sys_enter_sendto for UDP sends.
SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint__sock__inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
	struct network_event evt = {};

	evt.cgroup_id = bpf_get_current_cgroup_id();
	evt.pid = current_pid();
	evt.netns = current_netns_inum();
	evt.protocol = (__u8)ctx->protocol;
	evt.family = ctx->family;
	evt.sport = ctx->sport;
	evt.dport = ctx->dport;
	evt.state = (__u8)ctx->newstate;
	evt.direction = NET_DIR_UNKNOWN;

	if (ctx->family == AF_INET6) {
		__builtin_memcpy(evt.saddr_v6, ctx->saddr_v6, sizeof(evt.saddr_v6));
		__builtin_memcpy(evt.daddr_v6, ctx->daddr_v6, sizeof(evt.daddr_v6));
	} else {
		evt.saddr = pack_ipv4(ctx->saddr);
		evt.daddr = pack_ipv4(ctx->daddr);
	}

	if (ctx->newstate == TCP_SYN_SENT) {
		evt.direction = NET_DIR_OUTBOUND;
	} else if (ctx->newstate == TCP_SYN_RECV) {
		evt.direction = NET_DIR_INBOUND;
	} else if (ctx->oldstate == TCP_SYN_SENT && ctx->newstate == TCP_ESTABLISHED) {
		evt.direction = NET_DIR_OUTBOUND;
	} else if (ctx->oldstate == TCP_SYN_RECV && ctx->newstate == TCP_ESTABLISHED) {
		evt.direction = NET_DIR_INBOUND;
	}

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx) {
	struct network_event evt = {};
	__u16 port = 0;
	__u16 family = 0;
	const void *addr = 0;

	if (ctx->id != __NR_sendto) {
		return 0;
	}

	evt.cgroup_id = bpf_get_current_cgroup_id();
	evt.pid = current_pid();
	evt.netns = current_netns_inum();
	evt.protocol = IPPROTO_UDP;
	evt.direction = NET_DIR_OUTBOUND;
	evt.state = 0;

	addr = (const void *)ctx->args[4];
	if (!read_sockaddr(addr, &port, &evt.daddr, evt.daddr_v6, &family)) {
		return 0;
	}

	evt.family = family;
	evt.dport = port;

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
