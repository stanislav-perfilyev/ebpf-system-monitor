// src/http/metrics.h — Prometheus text exposition format
// https://prometheus.io/docs/instrumenting/exposition_formats/
//
// Provides:
//   PrometheusMetrics::from_reporter() → Prometheus text (for /metrics endpoint)
//   PrometheusMetrics::from_processor() → DPDK-sim throughput metrics

#pragma once
#include "../stats_reporter.h"
#include "../dpdk_sim/packet_processor.h"
#include <chrono>
#include <sstream>
#include <string>

namespace http {

class PrometheusMetrics {
public:
    /// Format StatsReporter data as Prometheus exposition text.
    [[nodiscard]] static std::string from_reporter(const ebpf::StatsReporter& reporter) {
        std::ostringstream out;
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Connection count gauge
        emit_help(out, "ebpf_active_connections",
                  "Number of tracked TCP connections");
        emit_type(out, "ebpf_active_connections", "gauge");
        out << "ebpf_active_connections " << reporter.connection_count()
            << " " << now_ms << "\n\n";

        // Per-connection counters
        emit_help(out, "ebpf_connection_bytes_tx_total",
                  "Bytes transmitted per connection");
        emit_type(out, "ebpf_connection_bytes_tx_total", "counter");
        emit_help(out, "ebpf_connection_bytes_rx_total",
                  "Bytes received per connection");
        emit_type(out, "ebpf_connection_bytes_rx_total", "counter");
        emit_help(out, "ebpf_connection_connects_total",
                  "TCP connect events per connection");
        emit_type(out, "ebpf_connection_connects_total", "counter");

        reporter.for_each([&](const ebpf::ConnectionKey&   key,
                              const ebpf::ConnectionStats& st) {
            char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
            in_addr sa{}, da{};
            sa.s_addr = key.src_ip;
            da.s_addr = key.dst_ip;
            inet_ntop(AF_INET, &sa, src, sizeof(src));
            inet_ntop(AF_INET, &da, dst, sizeof(dst));

            const std::string labels =
                "{comm=\"" + st.comm +
                "\",pid=\""      + std::to_string(key.pid) +
                "\",src=\""      + std::string(src) + ":" + std::to_string(ntohs(key.src_port)) +
                "\",dst=\""      + std::string(dst) + ":" + std::to_string(ntohs(key.dst_port)) +
                "\"}";

            out << "ebpf_connection_bytes_tx_total"   << labels << " " << st.bytes_tx    << " " << now_ms << "\n";
            out << "ebpf_connection_bytes_rx_total"   << labels << " " << st.bytes_rx    << " " << now_ms << "\n";
            out << "ebpf_connection_connects_total"   << labels << " " << st.connects    << " " << now_ms << "\n";
        });

        return out.str();
    }

    /// Format DPDK-sim BatchProcessor stats.
    template <std::size_t R, std::size_t P>
    [[nodiscard]] static std::string from_processor(const dpdk_sim::BatchProcessor<R, P>& proc) {
        std::ostringstream out;
        const auto& s = proc.stats();
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        emit_help(out, "dpdk_sim_packets_processed_total", "Total packets processed");
        emit_type(out, "dpdk_sim_packets_processed_total", "counter");
        out << "dpdk_sim_packets_processed_total " << s.pkts_processed << " " << now_ms << "\n\n";

        emit_help(out, "dpdk_sim_packets_dropped_total", "Total packets dropped (ring full)");
        emit_type(out, "dpdk_sim_packets_dropped_total", "counter");
        out << "dpdk_sim_packets_dropped_total " << s.pkts_dropped << " " << now_ms << "\n\n";

        emit_help(out, "dpdk_sim_bytes_processed_total", "Total bytes processed");
        emit_type(out, "dpdk_sim_bytes_processed_total", "counter");
        out << "dpdk_sim_bytes_processed_total " << s.bytes_processed << " " << now_ms << "\n\n";

        emit_help(out, "dpdk_sim_pool_available", "Free objects in memory pool");
        emit_type(out, "dpdk_sim_pool_available", "gauge");
        out << "dpdk_sim_pool_available " << proc.pool().available() << " " << now_ms << "\n\n";

        return out.str();
    }

private:
    static void emit_help(std::ostringstream& out,
                          std::string_view name, std::string_view help) {
        out << "# HELP " << name << " " << help << "\n";
    }
    static void emit_type(std::ostringstream& out,
                          std::string_view name, std::string_view type) {
        out << "# TYPE " << name << " " << type << "\n";
    }
};

} // namespace http
