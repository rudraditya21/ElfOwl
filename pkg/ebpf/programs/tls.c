// ANCHOR: TLS ClientHello Monitor - Apr 26, 2026
// Captures outbound TLS ClientHello bytes from syscall write/send paths for JA3 parsing.

#include "common.h"

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_MIN_RECORD_LEN 9
#define TLS_METADATA_MAX 1024

struct tls_event {
	__u32 pid;
	__u16 family;
	__u8 protocol;
	__u8 direction;
	__u16 src_port;
	__u16 dst_port;
	__u64 cgroup_id;
	__u32 length;
	__u8 metadata[TLS_METADATA_MAX];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tls_events SEC(".maps");

// ANCHOR: TLS event scratch map - Fix: BPF stack overflow with 512-byte metadata - Apr 26, 2026
// BPF stack limit is 512 bytes total; tls_event with 512-byte metadata overflows it.
// Use a per-CPU array as scratch space so the struct lives in map memory, not the stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tls_event);
} tls_scratch SEC(".maps");

struct sys_enter_write_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	unsigned int fd;
	const char *buf;
	size_t count;
};

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

struct sys_enter_writev_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	unsigned int fd;
	const struct iovec *vec;
	unsigned long vlen;
};

// ANCHOR: is_tls_client_hello strict validation - Fix: non-TLS writes misidentified - Apr 26, 2026
// Validates content_type(0x16) + record version(0x0301-0x0304) + handshake_type(0x01).
// Record-layer version check filters out non-TLS data that starts with 0x16 by coincidence.
static __always_inline int is_tls_client_hello(const __u8 *buf, __u64 len)
{
	__u8 content_type = 0;
	__u8 rec_ver_major = 0;
	__u8 rec_ver_minor = 0;
	__u8 handshake_type = 0;

	if (!buf || len < TLS_MIN_RECORD_LEN) {
		return 0;
	}

	if (bpf_probe_read_user(&content_type, sizeof(content_type), buf) < 0) {
		return 0;
	}
	if (content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
		return 0;
	}

	// Record-layer version: major must be 0x03, minor 0x01-0x04 (TLS 1.0-1.3).
	if (bpf_probe_read_user(&rec_ver_major, sizeof(rec_ver_major), buf + 1) < 0) {
		return 0;
	}
	if (rec_ver_major != 0x03) {
		return 0;
	}
	if (bpf_probe_read_user(&rec_ver_minor, sizeof(rec_ver_minor), buf + 2) < 0) {
		return 0;
	}
	if (rec_ver_minor < 0x01 || rec_ver_minor > 0x04) {
		return 0;
	}

	if (bpf_probe_read_user(&handshake_type, sizeof(handshake_type), buf + 5) < 0) {
		return 0;
	}
	return handshake_type == TLS_HANDSHAKE_TYPE_CLIENT_HELLO;
}

// ANCHOR: bulk copy_tls_metadata - Fix: byte-loop unroll blew verifier insn limit - Apr 26, 2026
// bpf_probe_read_user copies the whole buffer in one call; no loop needed.
static __always_inline __u32 copy_tls_metadata(const __u8 *buf, __u64 len, __u8 dst[TLS_METADATA_MAX])
{
	__u32 cap = len > TLS_METADATA_MAX ? TLS_METADATA_MAX : (__u32)len;
	if (bpf_probe_read_user(dst, cap, buf) < 0) {
		return 0;
	}
	return cap;
}


static __always_inline void fill_tls_event(struct tls_event *evt, const __u8 *buf, __u64 len)
{
	evt->pid = current_pid();
	evt->family = 0;
	evt->protocol = IPPROTO_TCP;
	evt->direction = 1;
	evt->src_port = 0;
	evt->dst_port = 0;
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->length = copy_tls_metadata(buf, len, evt->metadata);
}

static __always_inline void debug_tls_hit(const char *syscall, __u64 len, __u8 first)
{
	bpf_printk("tls %s hit pid=%d len=%llu first=%x\n", syscall, current_pid(), len, first);
}

SEC("tracepoint/syscalls/sys_enter_write")
int tls_write_monitor(struct sys_enter_write_ctx *ctx)
{
	__u32 key = 0;
	__u8 first = 0;

	if (!is_tls_client_hello((const __u8 *)ctx->buf, ctx->count)) {
		return 0;
	}

	struct tls_event *evt = bpf_map_lookup_elem(&tls_scratch, &key);
	if (!evt) {
		return 0;
	}

	if (ctx->buf) {
		bpf_probe_read_user(&first, sizeof(first), ctx->buf);
	}
	debug_tls_hit("write", (__u64)ctx->count, first);
	fill_tls_event(evt, (const __u8 *)ctx->buf, ctx->count);
	SUBMIT_EVENT(ctx, tls_events, evt);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tls_sendto_monitor(struct sys_enter_sendto_ctx *ctx)
{
	__u32 key = 0;
	__u8 first = 0;

	if (!is_tls_client_hello((const __u8 *)ctx->buff, (__u64)ctx->len)) {
		return 0;
	}

	struct tls_event *evt = bpf_map_lookup_elem(&tls_scratch, &key);
	if (!evt) {
		return 0;
	}

	if (ctx->buff) {
		bpf_probe_read_user(&first, sizeof(first), ctx->buff);
	}
	debug_tls_hit("sendto", (__u64)ctx->len, first);
	fill_tls_event(evt, (const __u8 *)ctx->buff, (__u64)ctx->len);
	SUBMIT_EVENT(ctx, tls_events, evt);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tls_writev_monitor(struct sys_enter_writev_ctx *ctx)
{
	__u32 key = 0;
	struct iovec iov = {};
	__u8 first = 0;

	if (ctx->vlen == 0 || !ctx->vec) {
		return 0;
	}

	if (bpf_probe_read_user(&iov, sizeof(iov), ctx->vec) < 0) {
		return 0;
	}

	if (!is_tls_client_hello((const __u8 *)iov.iov_base, (__u64)iov.iov_len)) {
		return 0;
	}

	struct tls_event *evt = bpf_map_lookup_elem(&tls_scratch, &key);
	if (!evt) {
		return 0;
	}

	if (iov.iov_base) {
		bpf_probe_read_user(&first, sizeof(first), iov.iov_base);
	}
	debug_tls_hit("writev", (__u64)iov.iov_len, first);
	fill_tls_event(evt, (const __u8 *)iov.iov_base, (__u64)iov.iov_len);
	SUBMIT_EVENT(ctx, tls_events, evt);
	return 0;
}


char LICENSE[] SEC("license") = "GPL";
