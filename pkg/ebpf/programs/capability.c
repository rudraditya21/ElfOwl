// ANCHOR: Capability Monitor eBPF Program - Mar 25, 2026
// Restores capability-check telemetry with syscall attribution.

#include "common.h"

// Capability constants (include/uapi/linux/capability.h).
#define CAP_SYS_ADMIN 21
#define CAP_SYS_MODULE 16
#define CAP_SYS_BOOT 22
#define CAP_SYS_PTRACE 19

// Event layout must match pkg/ebpf/types.go: CapabilityEvent.
struct capability_event {
	__u32 pid;
	__u32 capability;
	__u8 check_type;
	__u32 syscall_id;
	__u64 cgroup_id;
	char syscall_name[32];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} capability_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u32);
} capability_syscalls SEC(".maps");

// ANCHOR: Capability event emit helper - Fix: missing cap tracepoint fallback - Mar 28, 2026
// Emits a normalized capability_event payload from either cap_capable or syscall fallback paths.
static __always_inline int emit_capability_event(void *ctx, __u32 pid, __u32 cap, __u8 check_type, __u32 syscall_id)
{
	struct capability_event evt = {};

	evt.pid = pid;
	evt.capability = cap;
	evt.check_type = check_type;
	evt.syscall_id = syscall_id;
	evt.cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(evt.syscall_name, sizeof(evt.syscall_name));

	bpf_perf_event_output(ctx, &capability_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

// ANCHOR: Capability syscall attribution - Feature: syscall_id mapping - Mar 25, 2026
// Track the last syscall id per PID for cap_capable events.
SEC("tracepoint/raw_syscalls/sys_enter")
int capability_syscall_track(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = current_pid();
	__u32 id = (__u32)ctx->id;

	bpf_map_update_elem(&capability_syscalls, &pid, &id, BPF_ANY);

	// ANCHOR: CAP_SYS_ADMIN syscall fallback - Fix: kernels without cap_capable tracepoint - Mar 28, 2026
	// Some kernels (including common cloud/VM builds) omit capability/cap_capable tracepoints.
	// Emit CAP_SYS_ADMIN usage events from privileged mount-family syscalls as a compatibility fallback.
	if (id == __NR_mount || id == __NR_umount2) {
		return emit_capability_event(ctx, pid, CAP_SYS_ADMIN, 2, id);
	}

	return 0;
}

SEC("tracepoint/capability/cap_capable")
int capability_monitor(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 pid = current_pid();
	__u32 cap = (__u32)ctx->args[2];
	__u32 syscall_id = 0;
	__u32 *found_id;

	if (cap != CAP_SYS_ADMIN &&
	    cap != CAP_SYS_MODULE &&
	    cap != CAP_SYS_BOOT &&
	    cap != CAP_SYS_PTRACE) {
		return 0;
	}

	found_id = bpf_map_lookup_elem(&capability_syscalls, &pid);
	if (found_id) {
		syscall_id = *found_id;
		bpf_map_delete_elem(&capability_syscalls, &pid);
	}

	return emit_capability_event(ctx, pid, cap, 1, syscall_id);
}

char LICENSE[] SEC("license") = "GPL";
