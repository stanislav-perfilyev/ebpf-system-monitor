// src/stats_reporter.h — агрегация и вывод статистики TCP соединений

#pragma once
#include "../include/common.h"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace ebpf {

struct ConnectionKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t pid;

    bool operator==(const ConnectionKey& o) const noexcept {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port &&
               pid == o.pid;
    }
};

struct ConnectionStats {
    std::string comm;
    uint32_t    uid       = 0;
    uint64_t    bytes_tx  = 0;
    uint64_t    bytes_rx  = 0;
    uint64_t    connects  = 0;
    uint64_t    timestamp = 0;
};

} // namespace ebpf

namespace std {
template<> struct hash<ebpf::ConnectionKey> {
    size_t operator()(const ebpf::ConnectionKey& k) const noexcept {
        size_t h = 0;
        auto mix = [&](auto v) { h ^= std::hash<decltype(v)>{}(v) + 0x9e3779b9 + (h<<6) + (h>>2); };
        mix(k.src_ip); mix(k.dst_ip); mix(k.src_port); mix(k.dst_port); mix(k.pid);
        return h;
    }
};
} // namespace std

namespace ebpf {

class StatsReporter {
public:
    /* Вызывается из ring buffer callback (может быть из потока BPF poll) */
    void record(const tcp_event& ev)
    {
        ConnectionKey key{ ev.src_ip, ev.dst_ip, ev.src_port, ev.dst_port, ev.pid };
        std::lock_guard<std::mutex> lk(mu_);
        auto& s = stats_[key];
        s.comm      = std::string(ev.comm, strnlen(ev.comm, 16));
        s.uid       = ev.uid;
        s.timestamp = ev.timestamp_ns;
        if (ev.action == TCP_ACTION_CONNECT) {
            s.connects++;
        } else {
            s.bytes_tx += ev.bytes_tx;
            s.bytes_rx += ev.bytes_rx;
        }
    }

    /* Вывод топ-N по суммарному трафику */
    void print_top(int n = 10) const
    {
        std::vector<std::pair<ConnectionKey, ConnectionStats>> items;
        {
            std::lock_guard<std::mutex> lk(mu_);
            items.assign(stats_.begin(), stats_.end());
        }

        std::sort(items.begin(), items.end(),
            [](const auto& a, const auto& b){
                return (a.second.bytes_tx + a.second.bytes_rx) >
                       (b.second.bytes_tx + b.second.bytes_rx);
            });

        std::cout << "\033[2J\033[H";  // clear screen
        std::cout << "═══════════════════════════════════════════════════════\n";
        std::cout << "  eBPF System Monitor — Top TCP Connections\n";
        std::cout << "═══════════════════════════════════════════════════════\n";
        std::cout << std::left
                  << std::setw(6)  << "PID"
                  << std::setw(16) << "COMM"
                  << std::setw(20) << "SRC"
                  << std::setw(20) << "DST"
                  << std::setw(10) << "TX"
                  << std::setw(10) << "RX"
                  << "\n" << std::string(80, '=') << "\n";

        int shown = 0;
        for (const auto& [k, s] : items) {
            if (shown++ >= n) break;
            std::cout << std::left
                      << std::setw(6)  << k.pid
                      << std::setw(16) << s.comm
                      << std::setw(20) << ip_port(k.src_ip, k.src_port)
                      << std::setw(20) << ip_port(k.dst_ip, k.dst_port)
                      << std::setw(10) << human_bytes(s.bytes_tx)
                      << std::setw(10) << human_bytes(s.bytes_rx)
                      << "\n";
        }
        std::cout << std::flush;
    }

    [[nodiscard]] size_t connection_count() const
    {
        std::lock_guard<std::mutex> lk(mu_);
        return stats_.size();
    }

    void clear()
    {
        std::lock_guard<std::mutex> lk(mu_);
        stats_.clear();
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<ConnectionKey, ConnectionStats> stats_;

    static std::string ip_port(uint32_t ip, uint16_t port)
    {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, buf, sizeof(buf));
        return std::string(buf) + ":" + std::to_string(port);
    }

    static std::string human_bytes(uint64_t b)
    {
        if (b < 1024)       return std::to_string(b) + "B";
        if (b < 1024*1024)  return std::to_string(b/1024) + "K";
        return std::to_string(b/(1024*1024)) + "M";
    }
};

} // namespace ebpf
