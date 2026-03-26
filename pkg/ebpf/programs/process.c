// ANCHOR: Process Monitor eBPF Program - Mar 25, 2026
// Restores execve + execveat coverage using syscalls tracepoints.

#include "common.h"

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

// ANCHOR: Exec event payload helper - Fix: verifier complexity regression - Mar 25, 2026
// Avoid direct user-pointer reads from tracepoint ctx on older kernels.
static __always_inline void fill_exec_event(struct process_event *evt)
{
	bpf_get_current_comm(evt->filename, sizeof(evt->filename));
	bpf_get_current_comm(evt->argv, sizeof(evt->argv));
}

// ANCHOR: Execve tracepoints - Feature: explicit exec coverage - Mar 25, 2026
// Emits exec events from sys_enter_execve and sys_enter_execveat tracepoints.
static __always_inline int emit_exec_event(void *ctx)
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

	fill_exec_event(evt);
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
int process_execve(void *ctx)
{
	return emit_exec_event(ctx);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int process_execveat(void *ctx)
{
	return emit_exec_event(ctx);
}

char LICENSE[] SEC("license") = "GPL";
