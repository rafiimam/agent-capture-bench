// SPDX-License-Identifier: MIT
/*
 * AgentCaptureBench: independent Linux process-execution oracle.
 *
 * Observes fork/clone and successful exec events through kernel tracepoints.
 * The recorder under test must not consume this event stream. Events are
 * filtered to the target command's descendant process tree.
 *
 * argv is captured at sys_enter_execve/sys_enter_execveat and joined to the
 * successful sched_process_exec event. Only the first 8 argv elements and
 * first 95 bytes per element are retained; args_truncated reports truncation.
 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "oracle_events.h"

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sched_process_fork {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    char parent_comm[ACB_TASK_COMM_LEN];
    __s32 parent_pid;
    char child_comm[ACB_TASK_COMM_LEN];
    __s32 child_pid;
};

struct trace_event_raw_sched_process_exec {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __u32 __data_loc_filename;
    __s32 pid;
    __s32 old_pid;
    char __data[0];
};

struct trace_event_raw_sched_process_exit {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    char comm[ACB_TASK_COMM_LEN];
    __s32 pid;
    __s32 prio;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} tracked_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);   /* child PID */
    __type(value, __u32); /* parent PID */
} parent_by_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32); /* thread ID executing execve */
    __type(value, struct acb_argv_data);
} pending_argv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct acb_argv_data);
} argv_scratch SEC(".maps");

static __always_inline __u32 target_pid(void)
{
    __u32 key = 0;
    __u32 *value = bpf_map_lookup_elem(&target_pid_map, &key);
    return value ? *value : 0;
}

static __always_inline int is_tracked(__u32 pid)
{
    __u8 *value = bpf_map_lookup_elem(&tracked_pids, &pid);
    return value != 0;
}

static __always_inline int is_target_or_descendant(__u32 pid)
{
    __u32 root = target_pid();
    return root != 0 && (pid == root || is_tracked(pid));
}

static __always_inline void remember_argv(void *user_argv, __u32 pid)
{
    __u32 zero = 0;
    struct acb_argv_data *data = bpf_map_lookup_elem(&argv_scratch, &zero);
    if (!data || !user_argv)
        return;

    /* Same BPF no-libcall constraint as zero_event below: 776 bytes.
     * sizeof(struct acb_argv_data) = 776 (97 words). Stores are volatile:
     * otherwise clang's loop-idiom pass converts the loop back into the
     * memset libcall that BPF cannot emit. */
    {
        volatile __u64 *words = (volatile __u64 *)data;

#pragma unroll
        for (int i = 0; i < (int)(sizeof(*data) / sizeof(__u64)); i++)
            words[i] = 0;
    }

#pragma unroll
    for (int i = 0; i < ACB_MAX_ARGS; i++) {
        unsigned long user_arg = 0;
        const void *slot = (const char *)user_argv + (i * sizeof(user_arg));
        if (bpf_probe_read_user(&user_arg, sizeof(user_arg), slot) != 0)
            break;
        if (user_arg == 0)
            break;

        long n = bpf_probe_read_user_str(data->argv[i], ACB_ARG_LEN,
                                         (const void *)user_arg);
        if (n <= 0)
            break;
        data->argc = i + 1;
        if (n >= ACB_ARG_LEN)
            data->truncated = 1;
    }

    /* If argv[8] exists, more arguments were present than this schema stores. */
    if (data->argc == ACB_MAX_ARGS) {
        unsigned long next_arg = 0;
        const void *slot = (const char *)user_argv +
                           (ACB_MAX_ARGS * sizeof(next_arg));
        if (bpf_probe_read_user(&next_arg, sizeof(next_arg), slot) == 0 &&
            next_arg != 0)
            data->truncated = 1;
    }

    bpf_map_update_elem(&pending_argv, &pid, data, BPF_ANY);
}

/* The BPF backend has no memset/memcpy libcall to emit: __builtin_memset on
 * the 1072-byte event struct makes clang request one and the compile fails
 * ("A call to built-in function 'memset' is not supported"). Zero and copy
 * with explicit unrolled word loops instead. Both sizes divide by 8:
 * sizeof(struct acb_event) = 1072 (134 words), argv block = 768 (96 words).
 * Accesses are volatile: a plain loop is converted BACK into a memset call
 * by clang's loop-idiom recognition, which fails the same way. */
static __always_inline void zero_event(struct acb_event *event)
{
    volatile __u64 *words = (volatile __u64 *)event;

#pragma unroll
    for (int i = 0; i < (int)(sizeof(*event) / sizeof(__u64)); i++)
        words[i] = 0;
}

static __always_inline void copy_argv(struct acb_event *event,
                                      const struct acb_argv_data *args)
{
    volatile __u64 *dst = (volatile __u64 *)event->argv;
    const volatile __u64 *src = (const volatile __u64 *)args->argv;

#pragma unroll
    for (int i = 0; i < (int)(sizeof(event->argv) / sizeof(__u64)); i++)
        dst[i] = src[i];
}

static __always_inline int emit_fork(__u32 parent_pid, __u32 child_pid,
                                      const char child_comm[ACB_TASK_COMM_LEN])
{
    struct acb_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    zero_event(event);
    event->ts_ns = bpf_ktime_get_ns();
    event->type = ACB_EVENT_FORK;
    event->pid = child_pid;
    event->ppid = parent_pid;
    __builtin_memcpy(event->comm, child_comm, ACB_TASK_COMM_LEN);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int capture_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    if (!is_target_or_descendant(tid))
        return 0;
    remember_argv((void *)ctx->args[1], tid);
    return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int capture_execveat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    if (!is_target_or_descendant(tid))
        return 0;
    /* execveat(dfd, filename, argv, envp, flags): argv is args[2]. */
    remember_argv((void *)ctx->args[2], tid);
    return 0;
}

SEC("tp/sched/sched_process_fork")
int capture_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 root = target_pid();
    __u32 parent = (__u32)ctx->parent_pid;
    __u32 child = (__u32)ctx->child_pid;
    if (root == 0 || (parent != root && !is_tracked(parent)))
        return 0;

    __u8 yes = 1;
    bpf_map_update_elem(&tracked_pids, &child, &yes, BPF_ANY);
    bpf_map_update_elem(&parent_by_pid, &child, &parent, BPF_ANY);
    emit_fork(parent, child, ctx->child_comm);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int capture_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    __u32 old_pid = (__u32)ctx->old_pid;
    __u32 root = target_pid();
    int tracked = is_tracked(pid) || (old_pid != pid && is_tracked(old_pid));
    if (root == 0 || (pid != root && !tracked))
        return 0;

    __u8 yes = 1;
    if (pid == root || (old_pid != pid && is_tracked(old_pid))) {
        bpf_map_update_elem(&tracked_pids, &pid, &yes, BPF_ANY);
        if (old_pid != pid) {
            __u32 *old_parent = bpf_map_lookup_elem(&parent_by_pid, &old_pid);
            if (old_parent) {
                __u32 parent_copy = *old_parent;
                bpf_map_update_elem(&parent_by_pid, &pid, &parent_copy, BPF_ANY);
            }
            bpf_map_delete_elem(&tracked_pids, &old_pid);
            bpf_map_delete_elem(&parent_by_pid, &old_pid);
        }
    }

    struct acb_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    zero_event(event);
    event->ts_ns = bpf_ktime_get_ns();
    event->type = ACB_EVENT_EXEC;
    event->pid = pid;
    event->old_pid = old_pid;

    __u32 *ppid = bpf_map_lookup_elem(&parent_by_pid, &pid);
    if (ppid)
        event->ppid = *ppid;

    bpf_get_current_comm(event->comm, sizeof(event->comm));
    __u32 filename_offset = ctx->__data_loc_filename & 0xffff;
    const char *filename = (const char *)ctx + filename_offset;
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), filename);

    struct acb_argv_data *args = bpf_map_lookup_elem(&pending_argv, &pid);
    if (!args && old_pid != pid)
        args = bpf_map_lookup_elem(&pending_argv, &old_pid);
    if (args) {
        event->argc = args->argc;
        event->args_truncated = args->truncated;
        copy_argv(event, args);
    }

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&pending_argv, &pid);
    if (old_pid != pid)
        bpf_map_delete_elem(&pending_argv, &old_pid);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int cleanup_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    if (is_target_or_descendant(pid)) {
        bpf_map_delete_elem(&tracked_pids, &pid);
        bpf_map_delete_elem(&parent_by_pid, &pid);
        bpf_map_delete_elem(&pending_argv, &pid);
    }
    return 0;
}
