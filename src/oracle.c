/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/types.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "oracle_events.h"

struct sink {
    FILE *out;
    unsigned long sequence;
};

static void json_string(FILE *out, const char *value, size_t max_len)
{
    fputc('"', out);
    size_t len = strnlen(value, max_len);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        switch (c) {
        case '"': fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\b': fputs("\\b", out); break;
        case '\f': fputs("\\f", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (c < 0x20)
                fprintf(out, "\\u%04x", c);
            else
                fputc(c, out);
        }
    }
    fputc('"', out);
}

static int handle_event(void *ctx, void *data, size_t size)
{
    struct sink *sink = ctx;
    const struct acb_event *event = data;
    if (size < sizeof(*event)) {
        fprintf(stderr, "warning: short ring-buffer event (%zu bytes)\n", size);
        return 0;
    }

    FILE *out = sink->out;
    fprintf(out,
            "{\"record_type\":\"event\",\"seq\":%lu,\"ts_ns\":%llu,"
            "\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,\"old_pid\":%u,"
            "\"comm\":",
            ++sink->sequence,
            (unsigned long long)event->ts_ns,
            event->type == ACB_EVENT_EXEC ? "exec" : "fork",
            event->pid, event->ppid, event->old_pid);
    json_string(out, event->comm, sizeof(event->comm));
    fputs(",\"filename\":", out);
    json_string(out, event->filename, sizeof(event->filename));
    fprintf(out, ",\"argc\":%u,\"args_truncated\":%s,\"argv\":[",
            event->argc, event->args_truncated ? "true" : "false");
    unsigned int argc = event->argc;
    if (argc > ACB_MAX_ARGS)
        argc = ACB_MAX_ARGS;
    for (unsigned int i = 0; i < argc; i++) {
        if (i)
            fputc(',', out);
        json_string(out, event->argv[i], sizeof(event->argv[i]));
    }
    fputs("]}\n", out);
    fflush(out);
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
        "Usage: %s --output FILE [--allow-root-target] -- COMMAND [ARG ...]\n"
        "\n"
        "Attach the eBPF oracle, then execute COMMAND as the target process.\n"
        "The target and its descendants are observed; unrelated process events\n"
        "are filtered out. If invoked through sudo, the target is dropped back\n"
        "to SUDO_UID/SUDO_GID before it is released.\n",
        program);
}

static int map_fd_by_name(struct bpf_object *obj, const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    return map ? bpf_map__fd(map) : -1;
}

static int attach_program(struct bpf_object *obj, const char *name,
                          struct bpf_link **links, size_t *link_count,
                          size_t max_links)
{
    struct bpf_program *program = bpf_object__find_program_by_name(obj, name);
    if (!program) {
        fprintf(stderr, "error: BPF program '%s' not found\n", name);
        return -ENOENT;
    }
    struct bpf_link *link = bpf_program__attach(program);
    long err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr, "error: attaching '%s': %s\n", name, strerror((int)-err));
        return (int)err;
    }
    if (*link_count >= max_links) {
        bpf_link__destroy(link);
        return -E2BIG;
    }
    links[(*link_count)++] = link;
    return 0;
}

static int drop_to_sudo_user(void)
{
    if (geteuid() != 0)
        return 0;

    const char *uid_text = getenv("SUDO_UID");
    const char *gid_text = getenv("SUDO_GID");
    if (!uid_text || !gid_text || !*uid_text || !*gid_text) {
        errno = EPERM;
        return -1;
    }

    char *end_uid = NULL;
    char *end_gid = NULL;
    unsigned long uid_value = strtoul(uid_text, &end_uid, 10);
    unsigned long gid_value = strtoul(gid_text, &end_gid, 10);
    if (!end_uid || *end_uid || !end_gid || *end_gid || uid_value == 0 ||
        uid_value > 0xffffffffUL || gid_value > 0xffffffffUL) {
        errno = EINVAL;
        return -1;
    }

    uid_t uid = (uid_t)uid_value;
    gid_t gid = (gid_t)gid_value;
    struct passwd *pw = getpwuid(uid);
    if (!pw) {
        errno = ENOENT;
        return -1;
    }

    if (initgroups(pw->pw_name, gid) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
        return -1;
    if (pw->pw_dir && *pw->pw_dir)
        setenv("HOME", pw->pw_dir, 1);
    unsetenv("SUDO_UID");
    unsetenv("SUDO_GID");
    unsetenv("SUDO_USER");
    return 0;
}

int main(int argc, char **argv)
{
    const char *output_path = NULL;
    bool allow_root_target = false;
    int separator = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            separator = i;
            break;
        }
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "--allow-root-target") == 0) {
            allow_root_target = true;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!output_path || separator < 0 || separator + 1 >= argc) {
        usage(argv[0]);
        return 2;
    }
    if (geteuid() == 0 && (!getenv("SUDO_UID") || !getenv("SUDO_GID")) &&
        !allow_root_target) {
        fprintf(stderr,
            "error: refusing to run the target command as root. Invoke this tool "
            "through sudo from an unprivileged account so the child can drop "
            "privileges, or explicitly pass --allow-root-target in an isolated "
            "test environment.\n");
        return 2;
    }

    FILE *out = fopen(output_path, "w");
    if (!out) {
        fprintf(stderr, "error: cannot open %s: %s\n", output_path, strerror(errno));
        return 1;
    }
    (void)fcntl(fileno(out), F_SETFD, FD_CLOEXEC);
    struct sink sink = {.out = out, .sequence = 0};

    struct bpf_object *obj = bpf_object__open_file("build/oracle.bpf.o", NULL);
    long open_err = libbpf_get_error(obj);
    if (open_err) {
        fprintf(stderr, "error: opening build/oracle.bpf.o: %s\n",
                strerror((int)-open_err));
        fclose(out);
        return 1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr,
            "error: loading eBPF object failed: %s. Check kernel BPF support, "
            "CAP_BPF/CAP_PERFMON or equivalent privileges, tracepoint availability, "
            "and kernel lockdown policy.\n", strerror(-err));
        bpf_object__close(obj);
        fclose(out);
        return 1;
    }

    struct bpf_link *links[5] = {0};
    size_t link_count = 0;
    const char *program_names[] = {
        "capture_execve", "capture_execveat", "capture_fork",
        "capture_exec", "cleanup_exit"
    };
    for (size_t i = 0; i < sizeof(program_names) / sizeof(program_names[0]); i++) {
        err = attach_program(obj, program_names[i], links, &link_count,
                             sizeof(links) / sizeof(links[0]));
        if (err)
            goto cleanup;
    }

    int target_map_fd = map_fd_by_name(obj, "target_pid_map");
    int ring_map_fd = map_fd_by_name(obj, "events");
    if (target_map_fd < 0 || ring_map_fd < 0) {
        fprintf(stderr, "error: required BPF maps not found\n");
        err = -ENOENT;
        goto cleanup;
    }

    struct ring_buffer *ring = ring_buffer__new(ring_map_fd, handle_event, &sink, NULL);
    if (!ring) {
        fprintf(stderr, "error: creating ring buffer failed\n");
        err = -errno;
        goto cleanup;
    }

    int gate[2];
    if (pipe2(gate, O_CLOEXEC) != 0) {
        fprintf(stderr, "error: creating target gate pipe: %s\n", strerror(errno));
        err = -errno;
        ring_buffer__free(ring);
        goto cleanup;
    }

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "error: fork: %s\n", strerror(errno));
        err = -errno;
        close(gate[0]);
        close(gate[1]);
        ring_buffer__free(ring);
        goto cleanup;
    }
    if (child == 0) {
        close(gate[1]);
        char go = 0;
        ssize_t got = read(gate[0], &go, 1);
        close(gate[0]);
        if (got != 1 || go != '1')
            _exit(125);

        if (geteuid() == 0 && getenv("SUDO_UID") && getenv("SUDO_GID")) {
            if (drop_to_sudo_user() != 0) {
                dprintf(STDERR_FILENO, "agentcap-oracle: privilege drop failed: %s\n",
                        strerror(errno));
                _exit(126);
            }
        }
        execvp(argv[separator + 1], &argv[separator + 1]);
        dprintf(STDERR_FILENO, "agentcap-oracle: execvp %s failed: %s\n",
                argv[separator + 1], strerror(errno));
        _exit(127);
    }

    close(gate[0]);
    __u32 key = 0;
    __u32 target_pid = (__u32)child;
    if (bpf_map_update_elem(target_map_fd, &key, &target_pid, BPF_ANY) != 0) {
        fprintf(stderr, "error: setting target PID in BPF map: %s\n", strerror(errno));
        err = -errno;
        close(gate[1]);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        ring_buffer__free(ring);
        goto cleanup;
    }

    fprintf(out,
        "{\"record_type\":\"metadata\",\"schema_version\":1,"
        "\"oracle\":\"agentcapturebench-ebpf-prototype\","
        "\"target_pid\":%u,\"clock\":\"CLOCK_MONOTONIC_NS\","
        "\"argv_limit\":%d,\"arg_bytes_limit\":%d}\n",
        target_pid, ACB_MAX_ARGS, ACB_ARG_LEN - 1);
    fflush(out);

    if (write(gate[1], "1", 1) != 1) {
        fprintf(stderr, "error: releasing target command failed\n");
        err = -EIO;
    }
    close(gate[1]);

    int child_status = 0;
    bool child_done = false;
    while (!child_done) {
        int poll_err = ring_buffer__poll(ring, 100);
        if (poll_err < 0 && poll_err != -EINTR) {
            fprintf(stderr, "warning: ring buffer poll: %s\n", strerror(-poll_err));
        }
        pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            child_done = true;
        } else if (waited < 0 && errno != EINTR) {
            fprintf(stderr, "error: waitpid: %s\n", strerror(errno));
            err = -errno;
            child_done = true;
        }
    }

    /* Drain already-submitted events after the target's final exit. */
    for (int i = 0; i < 5; i++)
        (void)ring_buffer__poll(ring, 10);
    fflush(out);
    ring_buffer__free(ring);

    for (size_t i = 0; i < link_count; i++)
        bpf_link__destroy(links[i]);
    link_count = 0;
    bpf_object__close(obj);
    fclose(out);

    if (err)
        return 1;
    if (WIFEXITED(child_status))
        return WEXITSTATUS(child_status);
    if (WIFSIGNALED(child_status))
        return 128 + WTERMSIG(child_status);
    return 1;

cleanup:
    for (size_t i = 0; i < link_count; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    fclose(out);
    return 1;
}
