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
    evt.cgroup_id = bpf_get_current_cgroup_id();

    // ANCHOR: File openat extraction - Feature: flags/filename/cgroup - Mar 23, 2026
    // Captures filename, open flags, and cgroup for pod correlation.
    // Uses flags to classify read vs write intent for compliance rules.
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), (void *)args->filename);
    evt.flags = args->flags;
    if ((evt.flags & O_WRONLY) || (evt.flags & O_RDWR)) {
        evt.operation = 1;  // write
    } else {
        evt.operation = 2;  // read
    }

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
