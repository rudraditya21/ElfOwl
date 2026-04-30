// ANCHOR: TLS ClientHello Monitor - Apr 26, 2026
// Captures outbound TLS ClientHello bytes from syscall write/send paths for JA3 parsing.

#include "common.h"

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_MIN_RECORD_LEN 9
#define TLS_METADATA_MAX 2048

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

// ANCHOR: TLS buffer 2048 - Fix: TLS 1.3 key_share truncation - Apr 29, 2026
// 1024 bytes was insufficient for PQ-hybrid key_share extensions (X25519Kyber768 = ~1200 bytes).
// 2048 bytes covers current and near-future hybrid key exchange groups without truncation.

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


// ANCHOR: dst_port extraction from socket sk_common - Bug: dst_port=0 broke cert probe - Apr 30, 2026
// sys_enter_* tracepoints carry only the fd, not the peer address. Walk the kernel task's
// file-descriptor table to reach the sock and read skc_dport / skc_family via CO-RE.
// Path: task->files->fdt->fd[fd] -> file->private_data (struct socket*) -> sock->sk -> sk_common
// skc_dport is stored in network byte order; bpf_ntohs converts to host order for userspace.
// Returns 0 on any read failure so the event is still emitted without port data.
static __always_inline __u16 fd_dst_port(unsigned int fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;

	struct files_struct *files = BPF_CORE_READ(task, files);
	if (!files)
		return 0;

	struct fdtable *fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return 0;

	struct file **fdarr = BPF_CORE_READ(fdt, fd);
	if (!fdarr)
		return 0;

	struct file *f = NULL;
	if (bpf_core_read(&f, sizeof(f), &fdarr[fd]) < 0 || !f)
		return 0;

	// file->private_data points to struct socket for socket fds.
	struct socket *sock = NULL;
	if (bpf_core_read(&sock, sizeof(sock), &f->private_data) < 0 || !sock)
		return 0;

	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;

	__u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
	__u16 family   = BPF_CORE_READ(sk, __sk_common.skc_family);

	// Store family so fill_tls_event can set evt->family correctly.
	// Return port in host byte order; caller sets evt->dst_port.
	(void)family; // accessed via separate fd_family() if needed
	return bpf_ntohs(dport_be);
}

static __always_inline __u16 fd_family(unsigned int fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;

	struct files_struct *files = BPF_CORE_READ(task, files);
	if (!files)
		return 0;

	struct fdtable *fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return 0;

	struct file **fdarr = BPF_CORE_READ(fdt, fd);
	if (!fdarr)
		return 0;

	struct file *f = NULL;
	if (bpf_core_read(&f, sizeof(f), &fdarr[fd]) < 0 || !f)
		return 0;

	struct socket *sock = NULL;
	if (bpf_core_read(&sock, sizeof(sock), &f->private_data) < 0 || !sock)
		return 0;

	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;

	return BPF_CORE_READ(sk, __sk_common.skc_family);
}

static __always_inline void fill_tls_event(struct tls_event *evt, const __u8 *buf, __u64 len,
					   unsigned int fd)
{
	evt->pid       = current_pid();
	evt->family    = fd_family(fd);
	evt->protocol  = IPPROTO_TCP;
	evt->direction = 1;
	evt->src_port  = 0;
	evt->dst_port  = fd_dst_port(fd);
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->length    = copy_tls_metadata(buf, len, evt->metadata);
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
	fill_tls_event(evt, (const __u8 *)ctx->buf, ctx->count, ctx->fd);
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
	fill_tls_event(evt, (const __u8 *)ctx->buff, (__u64)ctx->len, (unsigned int)ctx->fd);
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
	fill_tls_event(evt, (const __u8 *)iov.iov_base, (__u64)iov.iov_len, ctx->fd);
	SUBMIT_EVENT(ctx, tls_events, evt);
	return 0;
}


// ANCHOR: sendmsg TLS capture - Fix: Go crypto/tls and DTLS coverage gap - Apr 29, 2026
// Go net/tls uses sendmsg(2) on non-blocking sockets; write/sendto miss those paths.
// OpenSSL also routes DTLS output through sendmsg. Hooking this syscall closes the gap.

// ANCHOR: tls_user_msghdr - Fix: vmlinux msghdr uses msg_iter not msg_iov - Apr 29, 2026
// vmlinux.h exposes the kernel-side struct msghdr which stores data in msg_iter (iov_iter),
// not msg_iov/msg_iovlen. bpf_probe_read_user reads from userspace memory, so we need
// the POSIX userspace layout. Defined manually to avoid the name collision with vmlinux.
struct tls_user_msghdr {
	void         *msg_name;
	__s32         msg_namelen;
	__s32         _pad;        /* 4-byte alignment gap before pointer on x86-64 */
	struct iovec *msg_iov;
	__u64         msg_iovlen;
	void         *msg_control;
	__u64         msg_controllen;
	__s32         msg_flags;
};

struct sys_enter_sendmsg_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long fd;
	const void *msg;   /* void* avoids collision with vmlinux struct msghdr */
	long flags;
};

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tls_sendmsg_monitor(struct sys_enter_sendmsg_ctx *ctx)
{
	__u32 key = 0;
	struct tls_user_msghdr hdr = {};
	struct iovec iov = {};
	__u8 first = 0;

	if (!ctx->msg) {
		return 0;
	}

	if (bpf_probe_read_user(&hdr, sizeof(hdr), ctx->msg) < 0) {
		return 0;
	}

	if (hdr.msg_iovlen == 0 || !hdr.msg_iov) {
		return 0;
	}

	if (bpf_probe_read_user(&iov, sizeof(iov), hdr.msg_iov) < 0) {
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
	debug_tls_hit("sendmsg", (__u64)iov.iov_len, first);
	fill_tls_event(evt, (const __u8 *)iov.iov_base, (__u64)iov.iov_len, (unsigned int)ctx->fd);
	SUBMIT_EVENT(ctx, tls_events, evt);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
