// ANCHOR: Network Monitor eBPF Program - Mar 25, 2026
// Adds TCP state, UDP send tracing, IPv6 tuples, and netns metadata.

#include "common.h"

// Event layout must match pkg/ebpf/types.go: NetworkEvent.
struct network_event {
	__u32 pid;
	__u16 family;
	__u16 sport;
	__u16 dport;
	__u32 saddr;
	__u32 daddr;
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	__u8 protocol;
	__u8 direction;
	__u8 state;
	__u32 netns;
	__u64 cgroup_id;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} network_events SEC(".maps");

#define NET_DIR_UNKNOWN 0
#define NET_DIR_OUTBOUND 1
#define NET_DIR_INBOUND 2

struct sys_enter_sendto_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long fd;
	const char *buff;
	long len;
	long flags;
	const struct sockaddr *addr;
	long addr_len;
};

static __always_inline __u32 pack_ipv4(const __u8 addr[4])
{
	return ((__u32)addr[0]) |
	       ((__u32)addr[1] << 8) |
	       ((__u32)addr[2] << 16) |
	       ((__u32)addr[3] << 24);
}

static __always_inline int read_udp_destination(const struct sockaddr *uaddr, __u32 addr_len,
				    __u16 *family, __u16 *dport, __u32 *daddr, __u8 daddr_v6[16])
{
	struct sockaddr_in dst4 = {};
	struct sockaddr_in6 dst6 = {};

	if (!uaddr || addr_len < sizeof(dst4)) {
		return -1;
	}

	if (bpf_probe_read_user(&dst4, sizeof(dst4), uaddr) < 0) {
		return -1;
	}

	if (dst4.sin_family == AF_INET) {
		*family = dst4.sin_family;
		*dport = dst4.sin_port;
		*daddr = dst4.sin_addr.s_addr;
		return 0;
	}

	if (addr_len < sizeof(dst6)) {
		return -1;
	}

	if (bpf_probe_read_user(&dst6, sizeof(dst6), uaddr) < 0) {
		return -1;
	}

	if (dst6.sin6_family != AF_INET6) {
		return -1;
	}

	*family = dst6.sin6_family;
	*dport = dst6.sin6_port;
	__builtin_memcpy(daddr_v6, &dst6.sin6_addr, sizeof(dst6.sin6_addr));
	return 0;
}

static __always_inline __u8 infer_direction(int oldstate, int newstate)
{
	if (newstate == TCP_SYN_SENT) {
		return NET_DIR_OUTBOUND;
	}
	if (newstate == TCP_SYN_RECV || newstate == TCP_NEW_SYN_RECV) {
		return NET_DIR_INBOUND;
	}
	return NET_DIR_UNKNOWN;
}

// ANCHOR: Network state + UDP coverage - Feature: advanced network telemetry - Mar 25, 2026
// Emits connection tuples from tcp_connect, inet_sock_set_state, and UDP sendto.
SEC("tracepoint/tcp/tcp_connect")
int network_monitor(struct trace_event_raw_tcp_event_sk *ctx)
{
	struct network_event evt = {};
	struct trace_event_raw_tcp_event_sk tcp = {};

	if (bpf_probe_read_kernel(&tcp, sizeof(tcp), ctx) < 0) {
		return 0;
	}

	if (tcp.family != AF_INET && tcp.family != AF_INET6) {
		return 0;
	}

	evt.pid = current_pid();
	evt.family = tcp.family;
	evt.sport = tcp.sport;
	evt.dport = tcp.dport;
	evt.protocol = IPPROTO_TCP;
	evt.direction = NET_DIR_OUTBOUND;
	evt.state = 0;
	evt.netns = current_netns_inum();
	evt.cgroup_id = bpf_get_current_cgroup_id();

	if (tcp.family == AF_INET) {
		evt.saddr = pack_ipv4(tcp.saddr);
		evt.daddr = pack_ipv4(tcp.daddr);
	} else {
		__builtin_memcpy(evt.saddr_v6, tcp.saddr_v6, sizeof(evt.saddr_v6));
		__builtin_memcpy(evt.daddr_v6, tcp.daddr_v6, sizeof(evt.daddr_v6));
	}

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

// SEC("tracepoint/inet_sock/inet_sock_set_state")
SEC("tracepoint/sock/inet_sock_set_state")
int network_state_monitor(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct network_event evt = {};
	struct trace_event_raw_inet_sock_set_state sk_state = {};

	if (bpf_probe_read_kernel(&sk_state, sizeof(sk_state), ctx) < 0) {
		return 0;
	}

	if (sk_state.family != AF_INET && sk_state.family != AF_INET6) {
		return 0;
	}

	evt.pid = current_pid();
	evt.family = sk_state.family;
	evt.sport = sk_state.sport;
	evt.dport = sk_state.dport;
	evt.protocol = (__u8)sk_state.protocol;
	evt.direction = infer_direction(sk_state.oldstate, sk_state.newstate);
	evt.state = (__u8)sk_state.newstate;
	evt.netns = current_netns_inum();
	evt.cgroup_id = bpf_get_current_cgroup_id();

	if (sk_state.family == AF_INET) {
		evt.saddr = pack_ipv4(sk_state.saddr);
		evt.daddr = pack_ipv4(sk_state.daddr);
	} else {
		__builtin_memcpy(evt.saddr_v6, sk_state.saddr_v6, sizeof(evt.saddr_v6));
		__builtin_memcpy(evt.daddr_v6, sk_state.daddr_v6, sizeof(evt.daddr_v6));
	}

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int network_udp_send(struct sys_enter_sendto_ctx *ctx)
{
	struct network_event evt = {};
	struct sys_enter_sendto_ctx sendto = {};
	__u16 family = 0;
	__u16 dport = 0;
	__u32 daddr = 0;
	__u8 daddr_v6[16] = {};

	if (bpf_probe_read_kernel(&sendto, sizeof(sendto), ctx) < 0) {
		return 0;
	}

	if (read_udp_destination(sendto.addr, (__u32)sendto.addr_len, &family, &dport, &daddr, daddr_v6) < 0) {
		return 0;
	}

	evt.pid = current_pid();
	evt.family = family;
	evt.sport = 0;
	evt.dport = dport;
	evt.saddr = 0;
	evt.daddr = daddr;
	evt.protocol = IPPROTO_UDP;
	evt.direction = NET_DIR_OUTBOUND;
	evt.state = 0;
	evt.netns = current_netns_inum();
	evt.cgroup_id = bpf_get_current_cgroup_id();
	__builtin_memcpy(evt.daddr_v6, daddr_v6, sizeof(evt.daddr_v6));

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
