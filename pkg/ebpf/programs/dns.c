// ANCHOR: DNS Monitor eBPF Program - Mar 23, 2026
// Captures DNS-oriented UDP sendto/recvfrom activity on port 53.

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

struct sys_enter_recvfrom_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	int fd;
	void *ubuf;
	__u64 size;
	unsigned int flags;
	struct sockaddr *addr;
	int *addr_len;
};

struct sys_exit_recvfrom_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long ret;
};

// Event layout must match pkg/ebpf/types.go: DNSEvent.
struct dns_event {
	__u32 pid;
	__u16 query_type;
	__u8 response_code;
	__u8 query_allowed;
	__u16 server_family;
	__u64 cgroup_id;
	char query_name[256];
	char server[16];
} __attribute__((packed));

struct dns_recv_state {
	const char *buf;
	const struct sockaddr *addr;
	const int *addr_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} dns_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct dns_recv_state);
} dns_recv_state_map SEC(".maps");

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

static __always_inline int read_dns_sockaddr(const struct sockaddr *uaddr, __u32 addr_len,
				    __u16 *family, __u16 *port, __u8 server[16])
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
		*port = bpf_ntohs(dst4.sin_port);
		__builtin_memcpy(server, &dst4.sin_addr.s_addr, sizeof(dst4.sin_addr.s_addr));
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
	*port = bpf_ntohs(dst6.sin6_port);
	__builtin_memcpy(server, &dst6.sin6_addr, sizeof(dst6.sin6_addr));
	return 0;
}

static __always_inline __u32 copy_label(const char *payload, __u64 payload_len, __u32 label_start,
				    char *name_out, __u32 out_idx, __u8 label_len)
{
#pragma clang loop unroll(full)
	for (int i = 0; i < 63; i++) {
		char c = 0;

		if (i >= label_len || out_idx >= 255 || label_start + i >= payload_len) {
			break;
		}

		bpf_probe_read_user(&c, sizeof(c), payload + label_start + i);
		name_out[out_idx++] = c;
	}

	return out_idx;
}

// Parse a common "two labels + root" DNS question (e.g., example.com).
static __always_inline void parse_dns_question(const char *payload, __u64 payload_len,
				       char *name_out, __u16 *query_type)
{
	__u32 offset = 12;
	__u32 out_idx = 0;
	__u8 label_len = 0;
	__u16 qtype_be = 0;

	if (!payload || payload_len < 16) {
		return;
	}

	bpf_probe_read_user(&label_len, sizeof(label_len), payload + offset);
	if (label_len == 0 || label_len > 63 || offset + 1 + label_len > payload_len) {
		return;
	}
	out_idx = copy_label(payload, payload_len, offset + 1, name_out, out_idx, label_len);
	offset += 1 + label_len;

	bpf_probe_read_user(&label_len, sizeof(label_len), payload + offset);
	if (label_len > 0) {
		if (label_len > 63 || offset + 1 + label_len > payload_len) {
			return;
		}
		if (out_idx < 255) {
			name_out[out_idx++] = '.';
		}
		out_idx = copy_label(payload, payload_len, offset + 1, name_out, out_idx, label_len);
		offset += 1 + label_len;
	}

	if (offset >= payload_len) {
		return;
	}

	bpf_probe_read_user(&label_len, sizeof(label_len), payload + offset);
	if (label_len != 0) {
		return;
	}
	offset += 1;

	name_out[out_idx] = '\0';
	if (offset + 2 > payload_len) {
		return;
	}

	bpf_probe_read_user(&qtype_be, sizeof(qtype_be), payload + offset);
	*query_type = bpf_ntohs(qtype_be);
}

static __always_inline void parse_dns_message(const char *payload, __u64 payload_len,
				      char *name_out, __u16 *query_type, __u8 *rcode)
{
	__u16 flags_be = 0;

	if (!payload || payload_len < 12) {
		return;
	}

	bpf_probe_read_user(&flags_be, sizeof(flags_be), payload + 2);
	*rcode = bpf_ntohs(flags_be) & 0x000f;
	parse_dns_question(payload, payload_len, name_out, query_type);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int dns_monitor(struct sys_enter_sendto_ctx *ctx)
{
	__u16 family = 0;
	__u16 dport = 0;
	__u8 server[16] = {};
	struct dns_event evt = {};

	if (read_dns_sockaddr(ctx->addr, (__u32)ctx->addr_len, &family, &dport, server) < 0) {
		return 0;
	}
	if (dport != 53) {
		return 0;
	}

	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.query_type = 0;
	evt.response_code = 0;
	evt.query_allowed = 1;
	evt.server_family = family;
	evt.cgroup_id = bpf_get_current_cgroup_id();
	__builtin_memcpy(evt.server, server, sizeof(evt.server));

	if (ctx->buff && ctx->len > 0) {
		__u16 query_type = 0;
		__u8 rcode = 0;
		parse_dns_message(ctx->buff, (__u64)ctx->len, evt.query_name, &query_type, &rcode);
		evt.query_type = query_type;
		evt.response_code = rcode;
	}
	if (evt.query_name[0] == '\0') {
		bpf_get_current_comm(evt.query_name, sizeof(evt.query_name));
	}

	bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

// ANCHOR: DNS recvfrom response parsing - Feature: response visibility - Mar 25, 2026
// Captures recvfrom buffer pointers on entry, parses responses on exit.
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int dns_recv_enter(struct sys_enter_recvfrom_ctx *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct dns_recv_state state = {};

	state.buf = ctx->ubuf;
	state.addr = ctx->addr;
	state.addr_len = ctx->addr_len;
	bpf_map_update_elem(&dns_recv_state_map, &pid, &state, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int dns_recv_exit(struct sys_exit_recvfrom_ctx *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct dns_recv_state *state;
	__u16 family = 0;
	__u16 sport = 0;
	__u8 server[16] = {};
	__u32 addr_len = 0;
	struct dns_event evt = {};

	state = bpf_map_lookup_elem(&dns_recv_state_map, &pid);
	if (!state) {
		return 0;
	}

	if (ctx->ret <= 0) {
		bpf_map_delete_elem(&dns_recv_state_map, &pid);
		return 0;
	}

	if (state->addr_len) {
		bpf_probe_read_user(&addr_len, sizeof(addr_len), state->addr_len);
	}

	if (read_dns_sockaddr(state->addr, addr_len, &family, &sport, server) < 0) {
		bpf_map_delete_elem(&dns_recv_state_map, &pid);
		return 0;
	}

	if (sport != 53) {
		bpf_map_delete_elem(&dns_recv_state_map, &pid);
		return 0;
	}

	evt.pid = pid;
	evt.query_type = 0;
	evt.response_code = 0;
	evt.query_allowed = 1;
	evt.server_family = family;
	evt.cgroup_id = bpf_get_current_cgroup_id();
	__builtin_memcpy(evt.server, server, sizeof(evt.server));

	if (state->buf && ctx->ret > 0) {
		__u16 query_type = 0;
		__u8 rcode = 0;
		parse_dns_message(state->buf, (__u64)ctx->ret, evt.query_name, &query_type, &rcode);
		evt.query_type = query_type;
		evt.response_code = rcode;
	}
	if (evt.query_name[0] == '\0') {
		bpf_get_current_comm(evt.query_name, sizeof(evt.query_name));
	}

	bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	bpf_map_delete_elem(&dns_recv_state_map, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
