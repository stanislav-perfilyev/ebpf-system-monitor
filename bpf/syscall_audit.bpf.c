// bpf/syscall_audit.bpf.c — аудит подозрительных системных вызовов
// Tracepoint: sys_enter (срабатывает на каждый syscall)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* Подозрительные syscall'ы (x86_64 номера) */
#define SYS_execve     59
#define SYS_execveat   322
#define SYS_ptrace     101
#define SYS_process_vm_readv  310
#define SYS_process_vm_writev 311
#define SYS_openat     257
#define SYS_socket     41
#define SYS_connect    42

/* Ring buffer для событий */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} syscall_events SEC(".maps");

/* UID whitelist — UID в этом map'е игнорируются (0 = root мониторим всегда) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u8);
} uid_whitelist SEC(".maps");

static __always_inline int is_suspicious(long nr)
{
    return (nr == SYS_execve     ||
            nr == SYS_execveat   ||
            nr == SYS_ptrace     ||
            nr == SYS_process_vm_readv  ||
            nr == SYS_process_vm_writev);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int audit_syscall(struct trace_event_raw_sys_enter *ctx)
{
    long nr = ctx->id;

    if (!is_suspicious(nr))
        return 0;

    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* Пропускаем whitelisted UID */
    u8 *wl = bpf_map_lookup_elem(&uid_whitelist, &uid);
    if (wl && *wl)
        return 0;

    struct syscall_event *ev = bpf_ringbuf_reserve(&syscall_events,
                                                    sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->uid          = uid;
    ev->pid          = bpf_get_current_pid_tgid() >> 32;
    ev->syscall_nr   = nr;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    /* Первые 3 аргумента */
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
