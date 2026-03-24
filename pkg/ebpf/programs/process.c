// ANCHOR: Process Monitor eBPF Program - Dec 27, 2025
// Kernel-native process execution monitoring via tracepoint
// Captures process spawning events for CIS 4.5 controls

#include "common.h"

#define MAX_ARGC 3
#define MAX_ARG_LEN 64

// Event structure matching enrichment.ProcessExecution
struct process_event {
	__u64 cgroup_id;
	__u64 capabilities;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char filename[256];
	char argv[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} process_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_event);
} process_event_heap SEC(".maps");

// ANCHOR: Process exec parsing - Feature: argv + exe path - Mar 24, 2026
// Parses execve/execveat arguments for best-effort command line capture.
static __always_inline void fill_exec_event(struct process_event *evt, const char *filename, const char *const *argv) {
	int offset = 0;

	bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename);

#pragma unroll
	for (int i = 0; i < MAX_ARGC; i++) {
		const char *argp = 0;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0) {
			break;
		}
		if (argp == 0) {
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

// ANCHOR: Raw syscall exec capture - Feature: libbpf tracepoint migration - Mar 24, 2026
// Uses raw_syscalls/sys_enter and syscall IDs to parse both execve and execveat.
SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx) {
	__u32 key = 0;
	struct process_event *evt = 0;
	const char *filename = 0;
	const char *const *argv = 0;
	long id = ctx->id;

	if (id != __NR_execve && id != __NR_execveat) {
		return 0;
	}

	evt = bpf_map_lookup_elem(&process_event_heap, &key);
	if (!evt) {
		return 0;
	}
	__builtin_memset(evt, 0, sizeof(*evt));

	if (id == __NR_execve) {
		filename = (const char *)ctx->args[0];
		argv = (const char *const *)ctx->args[1];
	} else {
		filename = (const char *)ctx->args[1];
		argv = (const char *const *)ctx->args[2];
	}

	evt->pid = current_pid();
	evt->uid = current_uid();
	evt->gid = current_gid();
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->capabilities = current_cap_effective();

	fill_exec_event(evt, filename, argv);
	SUBMIT_EVENT(ctx, process_events, evt);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
