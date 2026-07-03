// tests/test_dpdk_sim.cpp — тесты DPDK-sim: SpscRing, MemoryPool, BatchProcessor

#include <gtest/gtest.h>
#include "../src/dpdk_sim/spsc_ring.h"
#include "../src/dpdk_sim/memory_pool.h"
#include "../src/dpdk_sim/packet_processor.h"
#include <atomic>
#include <thread>
#include <vector>

using namespace dpdk_sim;

// ── SpscRing ──────────────────────────────────────────────────────────────

TEST(SpscRing, InitiallyEmpty) {
    SpscRing<int, 16> ring;
    EXPECT_TRUE(ring.empty());
    EXPECT_FALSE(ring.full());
    EXPECT_EQ(ring.size(), 0u);
}

TEST(SpscRing, EnqueueDequeue) {
    SpscRing<int, 8> ring;
    EXPECT_TRUE(ring.enqueue(42));
    EXPECT_EQ(ring.size(), 1u);
    int val = 0;
    EXPECT_TRUE(ring.dequeue(val));
    EXPECT_EQ(val, 42);
    EXPECT_TRUE(ring.empty());
}

TEST(SpscRing, FillAndDrain) {
    SpscRing<int, 8> ring;
    for (int i = 0; i < 8; ++i) EXPECT_TRUE(ring.enqueue(i));
    EXPECT_TRUE(ring.full());
    EXPECT_FALSE(ring.enqueue(99));  // full — rejected

    for (int i = 0; i < 8; ++i) {
        int v = -1;
        EXPECT_TRUE(ring.dequeue(v));
        EXPECT_EQ(v, i);
    }
    EXPECT_TRUE(ring.empty());
}

TEST(SpscRing, BurstEnqueueDequeue) {
    SpscRing<int, 64> ring;
    std::array<int, 32> src{}, dst{};
    for (int i = 0; i < 32; ++i) src[static_cast<size_t>(i)] = i;

    EXPECT_EQ(ring.enqueue_burst(src.data(), 32), 32u);
    EXPECT_EQ(ring.size(), 32u);

    const size_t got = ring.dequeue_burst(dst.data(), 32);
    EXPECT_EQ(got, 32u);
    for (int i = 0; i < 32; ++i)
        EXPECT_EQ(dst[static_cast<size_t>(i)], i);
}

TEST(SpscRing, BurstPartialFull) {
    SpscRing<int, 8> ring;
    std::array<int, 8> src{1,2,3,4,5,6,7,8};
    // Fill 6
    EXPECT_EQ(ring.enqueue_burst(src.data(), 6), 6u);
    // Try to enqueue 4 more — only 2 fit
    EXPECT_EQ(ring.enqueue_burst(src.data(), 4), 2u);
    EXPECT_TRUE(ring.full());
}

TEST(SpscRing, WrapAround) {
    SpscRing<int, 4> ring;
    // Fill, drain halfway, fill again — tests index wrap
    for (int i = 0; i < 4; ++i) ASSERT_TRUE(ring.enqueue(i));
    int v = -1;
    ASSERT_TRUE(ring.dequeue(v)); ASSERT_TRUE(ring.dequeue(v));  // drain 2
    ASSERT_TRUE(ring.enqueue(10)); ASSERT_TRUE(ring.enqueue(11));
    EXPECT_TRUE(ring.full());
    for (int expected : {2, 3, 10, 11}) {
        ASSERT_TRUE(ring.dequeue(v));
        EXPECT_EQ(v, expected);
    }
}

TEST(SpscRing, ThreadSafeSPSC) {
    SpscRing<int, 1024> ring;
    constexpr int N = 500;
    std::atomic<int> sum{0};

    std::thread producer([&] {
        for (int i = 1; i <= N; ++i)
            while (!ring.enqueue(i)) std::this_thread::yield();
    });
    std::thread consumer([&] {
        int received = 0;
        while (received < N) {
            int v = 0;
            if (ring.dequeue(v)) { sum.fetch_add(v); ++received; }
        }
    });
    producer.join();
    consumer.join();

    EXPECT_EQ(sum.load(), N * (N + 1) / 2);
}

// ── MemoryPool ────────────────────────────────────────────────────────────

TEST(MemoryPool, InitialAvailability) {
    MemoryPool<int, 64> pool;
    EXPECT_EQ(pool.available(), 64u);
    EXPECT_EQ(pool.capacity(), 64u);
    EXPECT_EQ(pool.in_use(), 0u);
}

TEST(MemoryPool, AllocFree) {
    MemoryPool<int, 8> pool;
    int* p = pool.alloc();
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(pool.available(), 7u);
    EXPECT_EQ(pool.in_use(), 1u);
    pool.free(p);
    EXPECT_EQ(pool.available(), 8u);
}

TEST(MemoryPool, Exhaustion) {
    MemoryPool<int, 4> pool;
    std::vector<int*> ptrs;
    for (int i = 0; i < 4; ++i) ptrs.push_back(pool.alloc());
    EXPECT_EQ(pool.alloc(), nullptr);
    for (auto* p : ptrs) pool.free(p);
    EXPECT_EQ(pool.available(), 4u);
}

TEST(MemoryPool, BurstAllocFree) {
    MemoryPool<int, 64> pool;
    std::array<int*, 32> ptrs{};
    EXPECT_EQ(pool.alloc_burst(ptrs.data(), 32), 32u);
    EXPECT_EQ(pool.available(), 32u);
    pool.free_burst(ptrs.data(), 32);
    EXPECT_EQ(pool.available(), 64u);
}

TEST(MemoryPool, TotalAllocsTracked) {
    MemoryPool<int, 8> pool;
    int* p1 = pool.alloc();
    int* p2 = pool.alloc();
    EXPECT_EQ(pool.total_allocs(), 2u);
    pool.free(p1); pool.free(p2);
}

// ── BatchProcessor ────────────────────────────────────────────────────────

TEST(BatchProcessor, SendAndProcess) {
    std::atomic<int> count{0};
    BatchProcessor<256, 128> proc([&](Packet* p) {
        count.fetch_add(static_cast<int>(p->len));
    });

    // Send 10 packets
    for (int i = 0; i < 10; ++i) {
        Packet* pkt = proc.alloc_packet();
        ASSERT_NE(pkt, nullptr);
        pkt->len = 100;
        EXPECT_TRUE(proc.send(pkt));
    }

    // Process burst
    const size_t processed = proc.process_burst();
    EXPECT_EQ(processed, 10u);
    EXPECT_EQ(count.load(), 1000);  // 10 * 100
    EXPECT_TRUE(proc.ring_empty());
}

TEST(BatchProcessor, StatsAccumulate) {
    BatchProcessor<256, 128> proc([](Packet* p) { (void)p; });

    for (int i = 0; i < 5; ++i) {
        Packet* pkt = proc.alloc_packet();
        ASSERT_NE(pkt, nullptr);
        pkt->len = 200;
        proc.send(pkt);
    }
    proc.process_burst();

    EXPECT_EQ(proc.stats().pkts_processed, 5u);
    EXPECT_EQ(proc.stats().bytes_processed, 1000u);
    EXPECT_EQ(proc.stats().bursts, 1u);
}

TEST(BatchProcessor, PoolReturnedAfterProcess) {
    BatchProcessor<256, 128> proc([](Packet*) {});
    const size_t initial = proc.pool().available();

    Packet* pkt = proc.alloc_packet();
    ASSERT_NE(pkt, nullptr);
    pkt->len = 1;
    proc.send(pkt);
    EXPECT_LT(proc.pool().available(), initial);

    proc.process_burst();
    // After processing, pool returns to initial
    EXPECT_EQ(proc.pool().available(), initial);
}

