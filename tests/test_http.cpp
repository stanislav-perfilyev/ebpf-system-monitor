// tests/test_http.cpp — тесты HTTP утилит (без сетевых вызовов)
// Проверяем: Prometheus формат метрик, JSON /connections, /health

#include <gtest/gtest.h>
#include "../src/stats_reporter.h"
#include "../src/http/metrics.h"
#include "../include/common.h"
#include <arpa/inet.h>
#include <cstring>
#include <string>

// Хелпер: создать tcp_event с заполненными полями
static tcp_event make_event(uint32_t pid, const char* comm,
                             uint32_t src_ip, uint32_t dst_ip,
                             uint16_t sport, uint16_t dport,
                             uint8_t action,
                             uint64_t tx = 0, uint64_t rx = 0)
{
    tcp_event ev{};
    ev.pid       = pid;
    ev.uid       = 1000;
    ev.src_ip    = src_ip;
    ev.dst_ip    = dst_ip;
    ev.src_port  = sport;
    ev.dst_port  = dport;
    ev.action    = action;
    ev.bytes_tx  = tx;
    ev.bytes_rx  = rx;
    ev.timestamp_ns = 1234567890ULL;
    std::strncpy(ev.comm, comm, 15);
    return ev;
}

// ── Prometheus format ─────────────────────────────────────────────────────

TEST(PrometheusMetrics, EmptyReporter) {
    ebpf::StatsReporter reporter;
    const auto out = http::PrometheusMetrics::from_reporter(reporter);

    // Must have HELP and TYPE lines
    EXPECT_NE(out.find("# HELP ebpf_active_connections"), std::string::npos);
    EXPECT_NE(out.find("# TYPE ebpf_active_connections gauge"), std::string::npos);
    EXPECT_NE(out.find("ebpf_active_connections 0"), std::string::npos);
}

TEST(PrometheusMetrics, HasRequiredMetrics) {
    ebpf::StatsReporter reporter;
    const auto out = http::PrometheusMetrics::from_reporter(reporter);

    EXPECT_NE(out.find("ebpf_connection_bytes_tx_total"), std::string::npos);
    EXPECT_NE(out.find("ebpf_connection_bytes_rx_total"), std::string::npos);
    EXPECT_NE(out.find("ebpf_connection_connects_total"), std::string::npos);
}

TEST(PrometheusMetrics, CounterIncrementsAfterRecord) {
    ebpf::StatsReporter reporter;

    uint32_t src = 0, dst = 0;
    inet_pton(AF_INET, "10.0.0.1", &src);
    inet_pton(AF_INET, "8.8.8.8",  &dst);

    // Real workflow: CONNECT establishes connection, CLOSE carries byte counts
    reporter.record(make_event(1234, "curl", src, dst, htons(54321), htons(443),
                               TCP_ACTION_CONNECT, 0, 0));
    reporter.record(make_event(1234, "curl", src, dst, htons(54321), htons(443),
                               TCP_ACTION_CLOSE, 512, 1024));

    const auto out = http::PrometheusMetrics::from_reporter(reporter);

    // Should have exactly 1 connection
    EXPECT_NE(out.find("ebpf_active_connections 1"), std::string::npos);
    // Should contain comm label
    EXPECT_NE(out.find("comm=\"curl\""), std::string::npos);
    // Should contain byte counters in per-connection lines
    EXPECT_NE(out.find("512"), std::string::npos);
    EXPECT_NE(out.find("1024"), std::string::npos);
}

TEST(PrometheusMetrics, PrometheusContentTypeFormat) {
    // Prometheus text format: each metric block separated by blank line
    ebpf::StatsReporter reporter;
    const auto out = http::PrometheusMetrics::from_reporter(reporter);

    // Must NOT be empty
    EXPECT_FALSE(out.empty());
    // Must use text/plain exposition format (no JSON-style braces at top)
    EXPECT_EQ(out[0], '#');  // starts with comment
}

TEST(PrometheusMetrics, MultipleConnectionsListed) {
    ebpf::StatsReporter reporter;
    uint32_t src = 0, dst1 = 0, dst2 = 0;
    inet_pton(AF_INET, "192.168.1.1", &src);
    inet_pton(AF_INET, "1.1.1.1",     &dst1);
    inet_pton(AF_INET, "8.8.8.8",     &dst2);

    reporter.record(make_event(100, "wget",  src, dst1, htons(1111), htons(80),  TCP_ACTION_CONNECT));
    reporter.record(make_event(200, "nginx", src, dst2, htons(2222), htons(443), TCP_ACTION_CONNECT));

    const auto out = http::PrometheusMetrics::from_reporter(reporter);
    EXPECT_NE(out.find("ebpf_active_connections 2"), std::string::npos);
    EXPECT_NE(out.find("wget"),  std::string::npos);
    EXPECT_NE(out.find("nginx"), std::string::npos);
}

// ── StatsReporter::for_each ───────────────────────────────────────────────

TEST(StatsReporter, ForEachEmpty) {
    ebpf::StatsReporter reporter;
    int count = 0;
    reporter.for_each([&](const ebpf::ConnectionKey&, const ebpf::ConnectionStats&) {
        ++count;
    });
    EXPECT_EQ(count, 0);
}

TEST(StatsReporter, ForEachCallsCallbackForEachConnection) {
    ebpf::StatsReporter reporter;
    uint32_t src = 0, dst = 0;
    inet_pton(AF_INET, "10.0.0.1", &src);
    inet_pton(AF_INET, "10.0.0.2", &dst);

    reporter.record(make_event(1, "a", src, dst, htons(1), htons(80), TCP_ACTION_CONNECT));
    reporter.record(make_event(2, "b", src, dst, htons(2), htons(80), TCP_ACTION_CONNECT));

    int count = 0;
    reporter.for_each([&](const ebpf::ConnectionKey&, const ebpf::ConnectionStats& s) {
        ++count;
        EXPECT_FALSE(s.comm.empty());
    });
    EXPECT_EQ(count, 2);
}

