// ANCHOR: Process Monitor eBPF Program - Dec 27, 2025
// Kernel-native process execution monitoring via tracepoint
// Captures process spawning events for CIS 4.5 controls

#include <uapi/linux/ptrace.h>
#include <uapi/linux/sched.h>
#include <linux/bpf.h>

#define MAX_ARGC 3
#define MAX_ARG_LEN 64

// Event structure matching enrichment.ProcessExecution
struct process_event {
    unsigned long cgroup_id;
    unsigned long capabilities;
    unsigned int pid;
    unsigned int uid;
    unsigned int gid;
    char filename[256];
    char argv[256];
};

// Perf buffer for sending events to userspace
// Will be instantiated in loader.go
BPF_PERF_OUTPUT(process_events);

// ANCHOR: Process exec parsing - Feature: argv + exe path - Mar 24, 2026
// Parses execve/execveat arguments for best-effort command line capture.
static __always_inline void fill_exec_event(struct process_event *evt, const char *filename, const char *const *argv) {
    char arg_buf[MAX_ARG_LEN] = {};
    int offset = 0;

    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), filename);

#pragma unroll
    for (int i = 0; i < MAX_ARGC; i++) {
        const char *argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0) {
            break;
        }
        if (argp == 0) {
            break;
        }

        int arg_len = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf), argp);
        if (arg_len <= 1) {
            continue;
        }

        if (offset > 0 && offset < (int)sizeof(evt->argv) - 1) {
            evt->argv[offset++] = ' ';
        }

#pragma unroll
        for (int j = 0; j < MAX_ARG_LEN; j++) {
            if (j >= arg_len - 1) {
                break;
            }
            if (offset >= (int)sizeof(evt->argv) - 1) {
                break;
            }
            evt->argv[offset++] = arg_buf[j];
        }
    }
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct process_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.capabilities = 0; // TODO: populate via CO-RE task_struct cred access.

    fill_exec_event(&evt, (const char *)args->filename, (const char *const *)args->argv);

    process_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    struct process_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid = bpf_get_current_uid_gid() >> 32;
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.capabilities = 0; // TODO: populate via CO-RE task_struct cred access.

    fill_exec_event(&evt, (const char *)args->filename, (const char *const *)args->argv);

    process_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
