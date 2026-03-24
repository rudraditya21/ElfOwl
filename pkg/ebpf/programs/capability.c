// ANCHOR: Capability Monitor eBPF Program - Dec 27, 2025
// Kernel-native Linux capability usage monitoring
// Captures dangerous capability usage for CIS 4.5.3 controls

#include "common.h"

// Capability constants (from include/uapi/linux/capability.h)
#define CAP_SYS_ADMIN       21
#define CAP_SYS_MODULE      16
#define CAP_SYS_BOOT        23
#define CAP_SYS_PTRACE      19

// Event structure matching enrichment.CapabilityUsage
struct capability_event {
	__u64 cgroup_id;
	__u32 pid;
	__u32 capability;    // CAP_* constant
	__u32 syscall_id;    // syscall number (best-effort)
	__u8 check_type;     // check=1, use=2
	char syscall_name[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} capability_events SEC(".maps");

// ANCHOR: Syscall attribution map - Feature: cap check context - Mar 24, 2026
// Tracks last seen syscall ID per PID to annotate capability checks.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1024);
} capability_last_syscall SEC(".maps");

// This tracepoint format includes cap and cap_opt integer fields.
struct trace_event_raw_cap_capable {
	struct trace_entry ent;
	int cap;
	int cap_opt;
	char __data[0];
};

// ANCHOR: Raw syscall tracking - Feature: last syscall cache - Mar 24, 2026
// Captures the last syscall ID to attribute subsequent cap_capable events.
SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx) {
	__u32 pid = current_pid();
	__u32 syscall_id = (__u32)ctx->id;

	bpf_map_update_elem(&capability_last_syscall, &pid, &syscall_id, BPF_ANY);
	return 0;
}

// Tracepoint: trace_cap_capable (capability check)
// Fires when kernel checks for process capability
SEC("tracepoint/capability/cap_capable")
int tracepoint__capability__cap_capable(struct trace_event_raw_cap_capable *ctx) {
	struct capability_event evt = {};
	__u32 pid = current_pid();
	__u32 *syscall_id = 0;

	evt.pid = pid;
	evt.check_type = 1;
	evt.cgroup_id = bpf_get_current_cgroup_id();
	evt.capability = (__u32)ctx->cap;
	bpf_get_current_comm(evt.syscall_name, sizeof(evt.syscall_name));

	syscall_id = bpf_map_lookup_elem(&capability_last_syscall, &pid);
	if (syscall_id) {
		evt.syscall_id = *syscall_id;
	}

	if (evt.capability != CAP_SYS_ADMIN &&
		evt.capability != CAP_SYS_MODULE &&
		evt.capability != CAP_SYS_BOOT &&
		evt.capability != CAP_SYS_PTRACE) {
		return 0;
	}

	SUBMIT_EVENT(ctx, capability_events, &evt);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
