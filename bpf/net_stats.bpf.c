// bpf/net_stats.bpf.c — XDP программа: статистика пакетов по протоколу L3/L4
// Аттачится к сетевому интерфейсу (lo, eth0 и т.д.)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* Ethernet type constants */
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

/* ── Статистика по протоколам ─────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16);
    __type(key, struct net_stats_key);
    __type(value, struct net_stats_val);
} proto_stats SEC(".maps");

/* ── Глобальный счётчик пакетов (для проверки что XDP работает) ─────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} total_packets SEC(".maps");

static __always_inline void
count_packet(u8 proto, u32 pkt_len)
{
    struct net_stats_key key = { .proto = proto };
    struct net_stats_val *val = bpf_map_lookup_elem(&proto_stats, &key);

    if (val) {
        val->packets++;
        val->bytes += pkt_len;
    } else {
        struct net_stats_val new_val = { .packets = 1, .bytes = pkt_len };
        bpf_map_update_elem(&proto_stats, &key, &new_val, BPF_ANY);
    }
}

SEC("xdp")
int xdp_net_stats(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Инкремент общего счётчика */
    u32 key = 0;
    u64 *total = bpf_map_lookup_elem(&total_packets, &key);
    if (total)
        (*total)++;

    /* Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    u16 eth_type = bpf_ntohs(eth->h_proto);
    u32 pkt_len = data_end - data;

    if (eth_type == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        count_packet(ip->protocol, pkt_len);
    } else if (eth_type == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        count_packet(ip6->nexthdr, pkt_len);
    }

    return XDP_PASS;   /* пропускаем все пакеты — только наблюдаем */
}

char LICENSE[] SEC("license") = "GPL";
