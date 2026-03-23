// ANCHOR: Capability Monitor eBPF Program - Dec 27, 2025
// Kernel-native Linux capability usage monitoring
// Captures dangerous capability usage for CIS 4.5.3 controls

#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

// Capability constants (from include/uapi/linux/capability.h)
#define CAP_SYS_ADMIN       21
#define CAP_SYS_MODULE      16
#define CAP_SYS_BOOT        23
#define CAP_SYS_PTRACE      19

// Event structure matching enrichment.CapabilityUsage
struct capability_event {
    unsigned long cgroup_id;
    unsigned int pid;
    unsigned int capability;    // CAP_* constant
    unsigned int syscall_id;    // syscall number (best-effort)
    unsigned char check_type;   // check=1, use=2
    char syscall_name[32];
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(capability_events);

// ANCHOR: Syscall attribution map - Feature: cap check context - Mar 24, 2026
// Tracks last seen syscall ID per PID to annotate capability checks.
BPF_HASH(capability_last_syscall, unsigned int, unsigned int, 1024);

// ANCHOR: Raw syscall tracking - Feature: last syscall cache - Mar 24, 2026
// Captures the last syscall ID to attribute subsequent cap_capable events.
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned int syscall_id = args->id;

    capability_last_syscall.update(&pid, &syscall_id);
    return 0;
}

// Tracepoint: trace_cap_capable (capability check)
// Fires when kernel checks for process capability
TRACEPOINT_PROBE(capability, cap_capable) {
    struct capability_event evt = {};
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned int *syscall_id = 0;

    evt.pid = pid;
    evt.check_type = 1;  // capability check
    evt.cgroup_id = bpf_get_current_cgroup_id();

    // ANCHOR: Capability tracepoint extraction - Feature: cap id/cgroup/comm - Mar 23, 2026
    // Captures capability ID, cgroup ID, and process comm for CIS 4.5.3.
    // Filters to high-risk capabilities to reduce noise.
    evt.capability = args->cap;
    bpf_get_current_comm(&evt.syscall_name, sizeof(evt.syscall_name));

    syscall_id = capability_last_syscall.lookup(&pid);
    if (syscall_id) {
        evt.syscall_id = *syscall_id;
    }

    if (evt.capability != CAP_SYS_ADMIN &&
        evt.capability != CAP_SYS_MODULE &&
        evt.capability != CAP_SYS_BOOT &&
        evt.capability != CAP_SYS_PTRACE) {
        return 0;
    }

    capability_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
