/* SPDX-License-Identifier: MIT */
#ifndef AGENTCAPTUREBENCH_ORACLE_EVENTS_H
#define AGENTCAPTUREBENCH_ORACLE_EVENTS_H

#include <linux/types.h>

#define ACB_TASK_COMM_LEN 16
#define ACB_FILENAME_LEN 256
#define ACB_MAX_ARGS 8
#define ACB_ARG_LEN 96

/* Values serialized in the JSONL event stream. */
enum acb_event_type {
    ACB_EVENT_FORK = 1,
    ACB_EVENT_EXEC = 2,
};

/* Stored in BPF maps, not allocated as a stack-local eBPF object. */
struct acb_argv_data {
    __u32 argc;
    __u32 truncated;
    char argv[ACB_MAX_ARGS][ACB_ARG_LEN];
};

/* Shared ABI between the eBPF program and the userspace ring-buffer reader. */
struct acb_event {
    __u64 ts_ns;        /* bpf_ktime_get_ns(): monotonic nanoseconds */
    __u32 type;
    __u32 pid;
    __u32 ppid;         /* 0 means unknown, not necessarily a root process */
    __u32 old_pid;      /* sched_process_exec's old PID; 0 for fork records */
    __u32 argc;
    __u32 args_truncated;
    char comm[ACB_TASK_COMM_LEN];
    char filename[ACB_FILENAME_LEN];
    char argv[ACB_MAX_ARGS][ACB_ARG_LEN];
};

#endif /* AGENTCAPTUREBENCH_ORACLE_EVENTS_H */
