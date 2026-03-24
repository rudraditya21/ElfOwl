// ANCHOR: DNS Monitor eBPF Program - Dec 27, 2025
// Kernel-native DNS query monitoring
// Captures DNS requests for CIS 4.6.4 controls (DNS exfiltration detection)

#include "common.h"

#define DNS_HEADER_LEN 12
#define DNS_MAX_LABELS 10
#define DNS_MAX_LABEL_LEN 32

// Event structure matching enrichment.DNSQuery
struct dns_event {
	__u32 pid;
	__u16 query_type;      // A=1, AAAA=28, MX=15, TXT=16, etc.
	__u8 response_code;    // 0=NOERROR, 1=FORMERR, 2=SERVFAIL, etc.
	__u8 query_allowed;    // 1=allowed, 0=suspicious/blocked
	__u64 cgroup_id;
	char query_name[256];  // Domain name being queried
	char server[16];       // DNS server IP (v4 or v6)
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} dns_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_event);
} dns_event_heap SEC(".maps");

struct dns_recvfrom_args {
	const void *buf;
	const void *addr;
	__u32 addr_len;
};

// ANCHOR: DNS recvfrom state tracking - Feature: response parsing - Mar 24, 2026
// Stores recvfrom buffers between sys_enter and sys_exit for payload inspection.
// Tracks recvfrom buffers so we can parse DNS responses on syscall exit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct dns_recvfrom_args);
	__uint(max_entries, 1024);
} dns_recvfrom_args_map SEC(".maps");

static __always_inline __u16 dns_ntohs(__u16 val) {
	return bpf_ntohs(val);
}

static __always_inline int read_sockaddr(const void *addr, __u16 *port, unsigned char server[16]) {
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
		*port = dns_ntohs(sin.sin_port);
		__builtin_memset(server, 0, 16);
		bpf_probe_read_user(server, sizeof(__u32), &sin.sin_addr.s_addr);
		return AF_INET;
	}

	if (sa.sa_family == AF_INET6) {
		struct sockaddr_in6 sin6 = {};
		if (bpf_probe_read_user(&sin6, sizeof(sin6), addr) < 0) {
			return 0;
		}
		*port = dns_ntohs(sin6.sin6_port);
		bpf_probe_read_user(server, sizeof(sin6.sin6_addr), &sin6.sin6_addr);
		return AF_INET6;
	}

	return 0;
}

// ANCHOR: DNS payload parsing - Feature: query/rcode/ipv6/recv - Mar 24, 2026
// Parses DNS header + QNAME + QTYPE from user buffer with bounded loops.
static __always_inline void parse_dns_payload(void *buf, unsigned int len, struct dns_event *evt) {
	unsigned char header[DNS_HEADER_LEN] = {};
	int offset = DNS_HEADER_LEN;
	int out = 0;

	if (len < DNS_HEADER_LEN) {
		return;
	}

	if (bpf_probe_read_user(header, sizeof(header), buf) < 0) {
		return;
	}

	evt->response_code = header[3] & 0x0F;

	// Skip if no questions
	if (header[4] == 0 && header[5] == 0) {
		return;
	}

#pragma unroll
	for (int i = 0; i < DNS_MAX_LABELS; i++) {
		unsigned char label_len = 0;
		if (offset >= len) {
			break;
		}
		if (bpf_probe_read_user(&label_len, sizeof(label_len), ((unsigned char *)buf) + offset) < 0) {
			break;
		}
		offset += 1;
		if (label_len == 0) {
			break;
		}

		if (label_len > DNS_MAX_LABEL_LEN) {
			label_len = DNS_MAX_LABEL_LEN;
		}

#pragma unroll
		for (int j = 0; j < DNS_MAX_LABEL_LEN; j++) {
			char c = 0;
			if (j >= label_len || offset + j >= len) {
				break;
			}
			if (bpf_probe_read_user(&c, sizeof(c), ((unsigned char *)buf) + offset + j) < 0) {
				break;
			}
			if (out < (int)sizeof(evt->query_name) - 1) {
				evt->query_name[out++] = c;
			}
		}

		if (out < (int)sizeof(evt->query_name) - 1) {
			evt->query_name[out++] = '.';
		}
		offset += label_len;
	}

	if (out > 0) {
		evt->query_name[out - 1] = 0;
	}

	if (offset + 2 <= len) {
		unsigned char qtype_bytes[2] = {};
		if (bpf_probe_read_user(qtype_bytes, sizeof(qtype_bytes), ((unsigned char *)buf) + offset) == 0) {
			evt->query_type = ((__u16)qtype_bytes[0] << 8) | qtype_bytes[1];
		}
	}
}

// ANCHOR: DNS syscall tracepoints - Feature: send/recv payload capture - Mar 24, 2026
// Hooks sendto/recvfrom to capture DNS query and response payloads.
SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx) {
	long id = ctx->id;
	__u32 pid = current_pid();

	if (id == __NR_sendto) {
		__u32 key = 0;
		struct dns_event *evt = 0;
		__u16 port = 0;
		const void *addr = (const void *)ctx->args[4];
		const void *buf = (const void *)ctx->args[1];
		__u32 len = (__u32)ctx->args[2];

		evt = bpf_map_lookup_elem(&dns_event_heap, &key);
		if (!evt) {
			return 0;
		}
		__builtin_memset(evt, 0, sizeof(*evt));

		evt->pid = pid;
		evt->query_allowed = 1;
		evt->cgroup_id = bpf_get_current_cgroup_id();

		if (!read_sockaddr(addr, &port, (unsigned char *)evt->server)) {
			return 0;
		}

		if (port != 53) {
			return 0;
		}

		parse_dns_payload((void *)buf, len, evt);
		SUBMIT_EVENT(ctx, dns_events, evt);
		return 0;
	}

	if (id == __NR_recvfrom) {
		struct dns_recvfrom_args args_state = {};

		args_state.buf = (const void *)ctx->args[1];
		args_state.addr = (const void *)ctx->args[4];
		args_state.addr_len = (__u32)ctx->args[5];
		bpf_map_update_elem(&dns_recvfrom_args_map, &pid, &args_state, BPF_ANY);
	}

	return 0;
}

// Parse DNS responses on recvfrom exit.
SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct trace_event_raw_sys_exit *ctx) {
	__u32 pid = current_pid();
	__u32 key = 0;
	struct dns_event *evt = 0;
	struct dns_recvfrom_args *args_state = 0;
	__u16 port = 0;
	long ret = ctx->ret;

	if (ctx->id != __NR_recvfrom) {
		return 0;
	}

	args_state = bpf_map_lookup_elem(&dns_recvfrom_args_map, &pid);
	if (!args_state) {
		return 0;
	}

	if (ret <= 0) {
		bpf_map_delete_elem(&dns_recvfrom_args_map, &pid);
		return 0;
	}

	evt = bpf_map_lookup_elem(&dns_event_heap, &key);
	if (!evt) {
		bpf_map_delete_elem(&dns_recvfrom_args_map, &pid);
		return 0;
	}
	__builtin_memset(evt, 0, sizeof(*evt));

	evt->pid = pid;
	evt->query_allowed = 1;
	evt->cgroup_id = bpf_get_current_cgroup_id();

	if (!read_sockaddr(args_state->addr, &port, (unsigned char *)evt->server)) {
		bpf_map_delete_elem(&dns_recvfrom_args_map, &pid);
		return 0;
	}

	if (port != 53) {
		bpf_map_delete_elem(&dns_recvfrom_args_map, &pid);
		return 0;
	}

	parse_dns_payload((void *)args_state->buf, (__u32)ret, evt);
	SUBMIT_EVENT(ctx, dns_events, evt);
	bpf_map_delete_elem(&dns_recvfrom_args_map, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
