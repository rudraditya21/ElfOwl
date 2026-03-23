// ANCHOR: Process Monitor eBPF Program - Dec 27, 2025
// Kernel-native process execution monitoring via tracepoint
// Captures process spawning events for CIS 4.5 controls

#include <uapi/linux/ptrace.h>
#include <uapi/linux/sched.h>
#include <linux/bpf.h>

// Event structure matching enrichment.ProcessExecution
struct process_event {
    unsigned int pid;
    unsigned int uid;
    unsigned int gid;
    unsigned long capabilities;
    char filename[256];
    char argv[256];
    unsigned long cgroup_id;
};

// Perf buffer for sending events to userspace
// Will be instantiated in loader.go
BPF_PERF_OUTPUT(process_events);

// Tracepoint: trace_sched_process_exec (process execution)
// Fires when a process is executed via execve/execveat
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct process_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    evt.cgroup_id = bpf_get_current_cgroup_id();

    // ANCHOR: Process tracepoint extraction - Feature: comm/filename/cgroup - Mar 23, 2026
    // Captures command name, best-effort filename, and cgroup for CIS 4.5 signals.
    // argv parsing and capability extraction require additional kernel helpers (Phase 3).
    bpf_get_current_comm(&evt.filename, sizeof(evt.filename));
    bpf_probe_read_kernel_str(&evt.argv, sizeof(evt.argv), args->filename);
    evt.capabilities = 0;

    process_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
