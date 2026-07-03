// bpf/tcp_tracer.bpf.c — трассировка TCP connect/close через kprobes
// Требует: clang -target bpf -O2 -g

#include "vmlinux.h"          // BTF-сгенерированные типы ядра (bpftool btf dump)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define AF_INET  2

/* ── Ring buffer для отправки событий в userspace ────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);  /* 4 МБ */
} tcp_events SEC(".maps");

/* ── Map PID → частичное событие (connect начат, но ещё не завершён) ── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct tcp_event);
} pending_connects SEC(".maps");

/* ── Фильтры (задаются из userspace через map) ───────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u32);
} filters SEC(".maps");   /* [0] = filter_pid (0 = все), [1] = filter_port (0 = все) */

static __always_inline int
should_filter(u32 pid, u16 dport)
{
    u32 key = 0;
    u32 *fpid = bpf_map_lookup_elem(&filters, &key);
    if (fpid && *fpid && *fpid != pid)
        return 1;

    key = 1;
    u32 *fport = bpf_map_lookup_elem(&filters, &key);
    if (fport && *fport && (u16)*fport != dport)
        return 1;

    return 0;
}

/* kprobe: tcp_connect — вызывается при установке TCP соединения */
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    if (should_filter(pid, dport))
        return 0;

    struct tcp_event ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid          = pid;
    ev.uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev.action       = TCP_ACTION_CONNECT;
    ev.af           = AF_INET;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));

    ev.src_ip   = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev.dst_ip   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev.dst_port = dport;

    /* Сохраняем как pending — bytes будут известны при close */
    bpf_map_update_elem(&pending_connects, &pid, &ev, BPF_ANY);

    /* Также сразу отправляем connect-событие */
    struct tcp_event *rbev = bpf_ringbuf_reserve(&tcp_events, sizeof(*rbev), 0);
    if (rbev) {
        *rbev = ev;
        bpf_ringbuf_submit(rbev, 0);
    }

    return 0;
}

/* kprobe: tcp_close — вызывается при закрытии TCP соединения */
SEC("kprobe/tcp_close")
int BPF_KPROBE(trace_tcp_close, struct sock *sk, long timeout)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct tcp_event *pending = bpf_map_lookup_elem(&pending_connects, &pid);

    struct tcp_event *rbev = bpf_ringbuf_reserve(&tcp_events, sizeof(*rbev), 0);
    if (!rbev)
        return 0;

    if (pending) {
        *rbev = *pending;
        bpf_map_delete_elem(&pending_connects, &pid);
    } else {
        rbev->pid       = pid;
        rbev->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        rbev->af        = AF_INET;
        bpf_get_current_comm(rbev->comm, sizeof(rbev->comm));
        rbev->src_ip    = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        rbev->dst_ip    = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        rbev->src_port  = BPF_CORE_READ(sk, __sk_common.skc_num);
        u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        rbev->dst_port  = __builtin_bswap16(dport);
    }

    rbev->timestamp_ns = bpf_ktime_get_ns();
    rbev->action       = TCP_ACTION_CLOSE;

    /* bytes_tx / bytes_rx из tcp_sock */
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rbev->bytes_tx = BPF_CORE_READ(tp, bytes_sent);
    rbev->bytes_rx = BPF_CORE_READ(tp, bytes_received);

    bpf_ringbuf_submit(rbev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
