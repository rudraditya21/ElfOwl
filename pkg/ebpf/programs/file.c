// ANCHOR: File Monitor eBPF Program - Dec 27, 2025
// Kernel-native file access monitoring
// Captures file write operations for CIS 4.5.5 controls

#include "common.h"

#ifndef O_WRONLY
#define O_WRONLY 1
#endif

#ifndef O_RDWR
#define O_RDWR 2
#endif

// Event structure matching enrichment.FileAccess
struct file_event {
	__u64 cgroup_id;
	__u32 pid;
	__u32 flags;       // Open flags (O_WRONLY, O_RDWR, etc.)
	__u32 mode;        // File mode (chmod/fchmodat/openat with O_CREAT)
	__u32 fd;          // File descriptor (write/pwrite best-effort)
	__u8 operation;    // write=1, read=2, chmod=3, unlink=4
	__u8 sensitive;    // 1=path matches sensitive prefixes
	char filename[256];
	char flags_str[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} file_events SEC(".maps");

static __always_inline unsigned char is_sensitive_path(const char *path) {
	if (path[0] != '/') {
		return 0;
	}

	if (path[1] == 'e' && path[2] == 't' && path[3] == 'c' && path[4] == '/') {
		return 1;
	}
	if (path[1] == 'r' && path[2] == 'o' && path[3] == 'o' && path[4] == 't' && path[5] == '/') {
		return 1;
	}
	if (path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/' &&
		path[5] == 'r' && path[6] == 'u' && path[7] == 'n' && path[8] == '/') {
		return 1;
	}
	if (path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/' &&
		path[5] == 'l' && path[6] == 'i' && path[7] == 'b' && path[8] == '/' &&
		path[9] == 'k' && path[10] == 'u' && path[11] == 'b' && path[12] == 'e' &&
		path[13] == 'l' && path[14] == 'e' && path[15] == 't' && path[16] == '/') {
		return 1;
	}
	if (path[1] == 'e' && path[2] == 't' && path[3] == 'c' && path[4] == '/' &&
		path[5] == 'k' && path[6] == 'u' && path[7] == 'b' && path[8] == 'e' &&
		path[9] == 'r' && path[10] == 'n' && path[11] == 'e' && path[12] == 't' &&
		path[13] == 'e' && path[14] == 's' && path[15] == '/') {
		return 1;
	}
	if (path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/' &&
		path[5] == 'r' && path[6] == 'u' && path[7] == 'n' && path[8] == '/' &&
		path[9] == 's' && path[10] == 'e' && path[11] == 'c' && path[12] == 'r' &&
		path[13] == 'e' && path[14] == 't' && path[15] == 's' && path[16] == '/') {
		return 1;
	}

	return 0;
}

// ANCHOR: File syscall expansion - Feature: write/chmod/unlink coverage - Mar 24, 2026
// Adds write, chmod, and unlink tracing for richer file activity signals.
SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx) {
	struct file_event evt = {};
	long id = ctx->id;

	evt.cgroup_id = bpf_get_current_cgroup_id();
	evt.pid = current_pid();

	if (id == __NR_openat) {
		const char *filename = (const char *)ctx->args[1];

		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);
		evt.flags = (__u32)ctx->args[2];
		evt.mode = (__u32)ctx->args[3];
		evt.sensitive = is_sensitive_path(evt.filename);
		evt.operation = ((evt.flags & O_WRONLY) || (evt.flags & O_RDWR)) ? 1 : 2;
	} else if (id == __NR_write || id == __NR_pwrite64) {
		evt.operation = 1;
		evt.fd = (__u32)ctx->args[0];
	} else if (id == __NR_chmod) {
		const char *filename = (const char *)ctx->args[0];

		evt.operation = 3;
		evt.mode = (__u32)ctx->args[1];
		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);
		evt.sensitive = is_sensitive_path(evt.filename);
	} else if (id == __NR_fchmodat) {
		const char *filename = (const char *)ctx->args[1];

		evt.operation = 3;
		evt.fd = (__u32)ctx->args[0];
		evt.mode = (__u32)ctx->args[2];
		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);
		evt.sensitive = is_sensitive_path(evt.filename);
	} else if (id == __NR_unlinkat) {
		const char *filename = (const char *)ctx->args[1];

		evt.operation = 4;
		evt.fd = (__u32)ctx->args[0];
		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);
		evt.sensitive = is_sensitive_path(evt.filename);
	} else {
		return 0;
	}

	SUBMIT_EVENT(ctx, file_events, &evt);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
