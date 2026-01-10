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
    unsigned int pid;
    unsigned int capability;    // CAP_* constant
    unsigned char check_type;   // check=1, use=2
    unsigned long cgroup_id;
    char syscall_name[32];
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(capability_events);

// Tracepoint: trace_cap_capable (capability check)
// Fires when kernel checks for process capability
TRACEPOINT_PROBE(capability, cap_capable) {
    struct capability_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.check_type = 1;  // capability check

    // TODO (Phase 2): Implement actual capability monitoring logic
    // - Extract capability ID from traceepoint data
    // - Filter for dangerous capabilities (CAP_SYS_ADMIN, etc.)
    // - Map to pod identity via cgroup
    // - Track which syscalls are using privileged capabilities
    // - Detect privilege escalation attempts

    capability_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
