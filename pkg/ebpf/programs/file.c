// ANCHOR: File Monitor eBPF Program - Dec 27, 2025
// Kernel-native file access monitoring
// Captures file write operations for CIS 4.5.5 controls

#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

// Event structure matching enrichment.FileAccess
struct file_event {
    unsigned int pid;
    unsigned int flags;         // Open flags (O_WRONLY, O_RDWR, etc.)
    unsigned char operation;    // write=1, read=2, chmod=3, unlink=4
    unsigned long cgroup_id;
    char filename[256];
    char flags_str[32];
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(file_events);

// Tracepoint: trace_vfs_write (file write operations)
// Fires when a file is written to
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct file_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.operation = 1;  // write

    // TODO (Phase 2): Implement actual file monitoring logic
    // - Extract filename from syscall arguments
    // - Read file permissions
    // - Track writes to system directories (/etc, /sys, etc.)
    // - Detect privilege escalation attempts
    // - Correlate with pod identity

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
