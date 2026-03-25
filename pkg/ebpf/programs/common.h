// ANCHOR: Shared eBPF CO-RE helpers - Feature: libbpf migration - Mar 24, 2026
// Common includes, syscall IDs, and task metadata helpers shared across eBPF modules.

#ifndef __ELF_OWL_EBPF_COMMON_H__
#define __ELF_OWL_EBPF_COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// Linux x86_64 syscall numbers used by raw_syscalls tracepoints.
// ANCHOR: Syscall ID arch guard - Safety: non-x86 builds - Mar 25, 2026
// Syscall numbers below are x86_64-specific; fail fast on other arches.
#ifndef __TARGET_ARCH_x86
#error "elf-owl eBPF syscall IDs are defined for x86_64 only"
#endif

#ifndef __NR_write
#define __NR_write 1
#endif

#ifndef __NR_pwrite64
#define __NR_pwrite64 18
#endif

#ifndef __NR_sendto
#define __NR_sendto 44
#endif

#ifndef __NR_recvfrom
#define __NR_recvfrom 45
#endif

#ifndef __NR_execve
#define __NR_execve 59
#endif

#ifndef __NR_chmod
#define __NR_chmod 90
#endif

#ifndef __NR_openat
#define __NR_openat 257
#endif

#ifndef __NR_unlinkat
#define __NR_unlinkat 263
#endif

#ifndef __NR_fchmodat
#define __NR_fchmodat 268
#endif

#ifndef __NR_execveat
#define __NR_execveat 322
#endif

#define SUBMIT_EVENT(ctx, map_name, evt_ptr) \
	bpf_perf_event_output(ctx, &map_name, BPF_F_CURRENT_CPU, evt_ptr, sizeof(*(evt_ptr)))

static __always_inline __u32 current_pid(void) {
	return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 current_uid(void) {
	return (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
}

static __always_inline __u32 current_gid(void) {
	return (__u32)(bpf_get_current_uid_gid() >> 32);
}

static __always_inline __u64 current_cap_effective(void) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u32 cap0 = 0;
	__u32 cap1 = 0;

	if (!task) {
		return 0;
	}

	cap0 = BPF_CORE_READ(task, real_cred, cap_effective.cap[0]);
	cap1 = BPF_CORE_READ(task, real_cred, cap_effective.cap[1]);
	return ((__u64)cap1 << 32) | cap0;
}

static __always_inline __u32 current_netns_inum(void) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!task) {
		return 0;
	}

	return BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
}

#endif // __ELF_OWL_EBPF_COMMON_H__
