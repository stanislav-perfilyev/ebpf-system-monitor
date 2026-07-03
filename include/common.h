/* include/common.h — общие структуры между BPF (kernel) и userspace (C++) */
#pragma once

#include <stdint.h>

/* ── TCP событие (tcp_tracer → userspace) ─────────────────────────────── */
struct tcp_event {
    uint64_t timestamp_ns;   /* ktime_get_ns() */
    uint32_t pid;
    uint32_t uid;
    char     comm[16];       /* имя процесса */
    uint32_t src_ip;         /* сетевой порядок байт */
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  af;             /* AF_INET = 2 */
    uint8_t  action;         /* 0 = connect, 1 = close */
    uint8_t  _pad[2];
    uint64_t bytes_tx;
    uint64_t bytes_rx;
};

/* ── Syscall событие (syscall_audit → userspace) ──────────────────────── */
struct syscall_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t uid;
    char     comm[16];
    long     syscall_nr;
    uint64_t args[3];        /* первые 3 аргумента */
};

/* ── Сетевая статистика (net_stats map) ───────────────────────────────── */
struct net_stats_key {
    uint8_t  proto;          /* IPPROTO_TCP=6, IPPROTO_UDP=17, etc */
    uint8_t  _pad[3];
};

struct net_stats_val {
    uint64_t packets;
    uint64_t bytes;
};

/* Действия tcp_event.action */
#define TCP_ACTION_CONNECT  0
#define TCP_ACTION_CLOSE    1
