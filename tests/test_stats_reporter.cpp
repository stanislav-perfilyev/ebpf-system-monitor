// tests/test_stats_reporter.cpp — тесты для StatsReporter (userspace)
// Не требует BPF, запускается без root.

#include <gtest/gtest.h>
#include "../src/stats_reporter.h"
#include "../include/common.h"
#include <arpa/inet.h>
#include <cstring>
#include <thread>

static tcp_event make_event(uint32_t pid, const char* comm,
                             uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint8_t action, uint64_t tx=0, uint64_t rx=0)
{
    tcp_event ev{};
    ev.pid       = pid;
    ev.action    = action;
    ev.src_ip    = src_ip;
    ev.dst_ip    = dst_ip;
    ev.src_port  = src_port;
    ev.dst_port  = dst_port;
    ev.bytes_tx  = tx;
    ev.bytes_rx  = rx;
    ev.timestamp_ns = 123456789;
    strncpy(ev.comm, comm, 15);
    return ev;
}

TEST(StatsReporter, InitiallyEmpty)
{
    ebpf::StatsReporter r;
    EXPECT_EQ(r.connection_count(), 0u);
}

TEST(StatsReporter, RecordConnectIncrementsCount)
{
    ebpf::StatsReporter r;
    auto ev = make_event(1234, "curl", 0x01010101, 0x08080808,
                          54321, 443, TCP_ACTION_CONNECT);
    r.record(ev);
    EXPECT_EQ(r.connection_count(), 1u);
}

TEST(StatsReporter, SameConnectionAggregatesBytes)
{
    ebpf::StatsReporter r;
    // connect
    r.record(make_event(42, "wget", 0xC0A80001, 0x08080808,
                         1234, 80, TCP_ACTION_CONNECT));
    // close с байтами
    r.record(make_event(42, "wget", 0xC0A80001, 0x08080808,
                         1234, 80, TCP_ACTION_CLOSE, 512, 4096));
    // повторный close (ещё байты)
    r.record(make_event(42, "wget", 0xC0A80001, 0x08080808,
                         1234, 80, TCP_ACTION_CLOSE, 100, 200));

    // Всё одно соединение
    EXPECT_EQ(r.connection_count(), 1u);
}

TEST(StatsReporter, DifferentPidsAreDistinct)
{
    ebpf::StatsReporter r;
    r.record(make_event(1, "proc1", 0x01010101, 0x02020202,
                         100, 80, TCP_ACTION_CONNECT));
    r.record(make_event(2, "proc2", 0x01010101, 0x02020202,
                         100, 80, TCP_ACTION_CONNECT));
    EXPECT_EQ(r.connection_count(), 2u);
}

TEST(StatsReporter, ClearResetsState)
{
    ebpf::StatsReporter r;
    r.record(make_event(1, "a", 1, 2, 100, 80, TCP_ACTION_CONNECT));
    r.record(make_event(2, "b", 3, 4, 200, 443, TCP_ACTION_CONNECT));
    EXPECT_EQ(r.connection_count(), 2u);
    r.clear();
    EXPECT_EQ(r.connection_count(), 0u);
}

TEST(StatsReporter, PrintTopDoesNotCrashOnEmpty)
{
    ebpf::StatsReporter r;
    EXPECT_NO_THROW(r.print_top(10));
}

TEST(StatsReporter, PrintTopDoesNotCrashWithData)
{
    ebpf::StatsReporter r;
    for (int i = 0; i < 15; ++i) {
        r.record(make_event(
            static_cast<uint32_t>(i), "proc",
            static_cast<uint32_t>(i), static_cast<uint32_t>(i+1),
            static_cast<uint16_t>(1000+i), 80,
            TCP_ACTION_CLOSE,
            static_cast<uint64_t>(i * 1024),
            static_cast<uint64_t>(i * 512)));
    }
    EXPECT_NO_THROW(r.print_top(10));
}

TEST(StatsReporter, ThreadSafeMultipleRecords)
{
    ebpf::StatsReporter r;
    // Имитация concurrent записи из нескольких потоков
    auto worker = [&r](uint32_t pid_base) {
        for (uint32_t i = 0; i < 100; ++i) {
            r.record(make_event(pid_base + i, "thr",
                                 i, i+1, static_cast<uint16_t>(i),
                                 80, TCP_ACTION_CONNECT));
        }
    };
    std::thread t1(worker, 0);
    std::thread t2(worker, 1000);
    t1.join();
    t2.join();
    EXPECT_GT(r.connection_count(), 0u);
}
