// ANCHOR: Process Monitor eBPF Program - Mar 25, 2026
// Restores execve + execveat coverage using syscalls tracepoints.

#include "common.h"

#define MAX_ARGC 3
#define MAX_ARG_LEN 64

// Event layout must match pkg/ebpf/types.go: ProcessEvent.
struct process_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u64 capabilities;
	char filename[256];
	char argv[256];
	__u64 cgroup_id;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} process_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_event);
} process_heap SEC(".maps");

struct sys_enter_execve_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

struct sys_enter_execveat_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	int dfd;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
	int flags;
};

// ANCHOR: Exec argv parsing helper - Fix: recover execveat visibility - Mar 25, 2026
// Best-effort argv reconstruction with bounded loops for verifier safety.
static __always_inline void fill_exec_event(struct process_event *evt, const char *filename, const char *const *argv)
{
	int offset = 0;

	if (filename) {
		bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename);
	}

#pragma unroll
	for (int i = 0; i < MAX_ARGC; i++) {
		const char *argp = 0;
		if (!argv || bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0) {
			break;
		}
		if (!argp) {
			break;
		}

		if (offset > 0 && offset < (int)sizeof(evt->argv) - 1) {
			evt->argv[offset++] = ' ';
		}

#pragma unroll
		for (int j = 0; j < MAX_ARG_LEN - 1; j++) {
			char c = 0;
			if (offset >= (int)sizeof(evt->argv) - 1) {
				break;
			}
			if (bpf_probe_read_user(&c, sizeof(c), argp + j) < 0) {
				break;
			}
			if (c == '\0') {
				break;
			}
			evt->argv[offset++] = c;
		}
	}
}

// ANCHOR: Execve tracepoints - Feature: explicit exec coverage - Mar 25, 2026
// Emits exec events from sys_enter_execve and sys_enter_execveat tracepoints.
static __always_inline int emit_exec_event(void *ctx, const char *filename, const char *const *argv)
{
	struct process_event *evt;
	__u32 key = 0;

	evt = bpf_map_lookup_elem(&process_heap, &key);
	if (!evt) {
		return 0;
	}
	__builtin_memset(evt, 0, sizeof(*evt));

	evt->pid = current_pid();
	evt->uid = current_uid();
	evt->gid = current_gid();
	evt->capabilities = current_cap_effective();
	evt->cgroup_id = bpf_get_current_cgroup_id();

	fill_exec_event(evt, filename, argv);
	if (evt->filename[0] == '\0') {
		bpf_get_current_comm(evt->filename, sizeof(evt->filename));
	}
	if (evt->argv[0] == '\0') {
		bpf_get_current_comm(evt->argv, sizeof(evt->argv));
	}

	SUBMIT_EVENT(ctx, process_events, evt);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int process_execve(struct sys_enter_execve_ctx *ctx)
{
	return emit_exec_event(ctx, ctx->filename, ctx->argv);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int process_execveat(struct sys_enter_execveat_ctx *ctx)
{
	return emit_exec_event(ctx, ctx->filename, ctx->argv);
}

char LICENSE[] SEC("license") = "GPL";
