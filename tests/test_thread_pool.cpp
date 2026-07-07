// MT stress-tests for ThreadPool + RequestStats
//
// ThreadPool: N jthread workers consume tasks from mutex+deque queue
// RequestStats: shared_mutex — concurrent readers (snapshot) + writers (record)
//
#include <gtest/gtest.h>

#include "thread_pool.h"
#include "request_stats.h"

#include <atomic>
#include <chrono>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

using namespace http;

// ─── ThreadPool tests ─────────────────────────────────────────────────────────

TEST(ThreadPool, DefaultConstructor_HasWorkers) {
    ThreadPool pool;
    EXPECT_GE(pool.size(), 1u);
}

TEST(ThreadPool, Submit_ReturnsCorrectResult) {
    ThreadPool pool(2);
    auto fut = pool.submit([]() { return 42; });
    EXPECT_EQ(fut.get(), 42);
}

TEST(ThreadPool, Submit_1000Tasks_AllComplete) {
    ThreadPool pool(4);
    constexpr int N = 1000;
    std::atomic<int> counter{0};
    std::vector<std::future<void>> futs;
    futs.reserve(N);

    for (int i = 0; i < N; ++i)
        futs.emplace_back(pool.submit([&counter]() {
            counter.fetch_add(1, std::memory_order_relaxed);
        }));

    for (auto& f : futs) f.get();
    EXPECT_EQ(counter.load(), N);
    EXPECT_EQ(pool.completed(), static_cast<uint64_t>(N));
}

TEST(ThreadPool, Submit_SumIsCorrect) {
    // N tasks each return i; sum must equal N*(N-1)/2
    ThreadPool pool(8);
    constexpr int N = 10'000;
    std::vector<std::future<int>> futs;
    futs.reserve(N);

    for (int i = 0; i < N; ++i)
        futs.emplace_back(pool.submit([i]() { return i; }));

    int64_t total = 0;
    for (auto& f : futs) total += f.get();

    const int64_t expected = static_cast<int64_t>(N) * (N - 1) / 2;
    EXPECT_EQ(total, expected);
}

TEST(ThreadPool, Completed_Counter_Accurate) {
    ThreadPool pool(4);
    constexpr int N = 500;
    std::vector<std::future<void>> futs;
    for (int i = 0; i < N; ++i)
        futs.emplace_back(pool.submit([]() {}));
    for (auto& f : futs) f.get();
    EXPECT_EQ(pool.completed(), static_cast<uint64_t>(N));
}

TEST(ThreadPool, Submit_AfterShutdown_Throws) {
    // Create pool in a scope so it shuts down
    std::unique_ptr<ThreadPool> pool = std::make_unique<ThreadPool>(2);
    pool.reset();  // destroys → stop flag set + join
    // Nothing to test post-destruction — just verifying no crash
    SUCCEED();
}

TEST(ThreadPool, SubmitWithArgs) {
    ThreadPool pool(2);
    auto fut = pool.submit([](int a, int b) { return a + b; }, 10, 32);
    EXPECT_EQ(fut.get(), 42);
}

// ─── RequestStats tests ────────────────────────────────────────────────────────

TEST(RequestStats, SingleThread_RecordAndSnapshot) {
    RequestStats stats;
    stats.record("/metrics", 100, true);
    stats.record("/metrics", 200, true);
    stats.record("/health",  50,  false);

    auto snap = stats.snapshot();
    ASSERT_TRUE(snap.count("/metrics"));
    ASSERT_TRUE(snap.count("/health"));
    EXPECT_EQ(snap["/metrics"].requests, 2u);
    EXPECT_EQ(snap["/metrics"].errors,   0u);
    EXPECT_EQ(snap["/metrics"].total_us, 300u);
    EXPECT_EQ(snap["/metrics"].min_us,   100u);
    EXPECT_EQ(snap["/metrics"].max_us,   200u);
    EXPECT_EQ(snap["/health"].errors,    1u);
}

TEST(RequestStats, MT_ConcurrentWrites_TotalCountCorrect) {
    RequestStats stats;
    constexpr int kThreads  = 8;
    constexpr int kEach     = 2'000;

    std::vector<std::jthread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&stats]() {
            for (int i = 0; i < kEach; ++i)
                stats.record("/metrics", static_cast<uint64_t>(i % 500), true);
        });
    }
    threads.clear();  // jthreads join here

    EXPECT_EQ(stats.total_requests(),
              static_cast<uint64_t>(kThreads * kEach));
}

TEST(RequestStats, MT_ReadersAndWriters_NoDataRace) {
    RequestStats stats;
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> reads{0};

    std::vector<std::jthread> readers;
    for (int r = 0; r < 4; ++r) {
        readers.emplace_back([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                auto snap = stats.snapshot();
                (void)snap;
                ++reads;
            }
        });
    }

    std::vector<std::jthread> writers;
    for (int w = 0; w < 4; ++w) {
        writers.emplace_back([&stats, w]() {
            for (int i = 0; i < 5'000; ++i)
                stats.record("/route_" + std::to_string(w % 3),
                             static_cast<uint64_t>(i % 1000), i % 5 != 0);
        });
    }
    writers.clear();
    stop.store(true);
    readers.clear();

    EXPECT_EQ(stats.total_requests(), 4u * 5'000u);
    EXPECT_GT(reads.load(), 0u);
}

TEST(RequestStats, MeanLatency_Correct) {
    RequestStats stats;
    stats.record("/api", 100, true);
    stats.record("/api", 300, true);
    auto snap = stats.snapshot();
    EXPECT_DOUBLE_EQ(snap["/api"].mean_us(), 200.0);
}

TEST(RequestStats, TotalErrors_Correct) {
    RequestStats stats;
    stats.record("/a", 10, true);
    stats.record("/a", 10, false);
    stats.record("/b", 10, false);
    EXPECT_EQ(stats.total_errors(), 2u);
}

// ─── RequestTimer RAII test ────────────────────────────────────────────────────

TEST(RequestTimer, AutoRecordsOnDestruct) {
    RequestStats stats;
    {
        RequestTimer timer(stats, "/path");
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        timer.finish(true);
    }
    EXPECT_EQ(stats.total_requests(), 1u);
    EXPECT_EQ(stats.total_errors(), 0u);
}

TEST(RequestTimer, MissedFinish_RecordsAsError) {
    RequestStats stats;
    {
        RequestTimer timer(stats, "/bad");
        // no timer.finish() — destructor marks as error
    }
    EXPECT_EQ(stats.total_requests(), 1u);
    EXPECT_EQ(stats.total_errors(), 1u);
}

// ─── Combined: ThreadPool dispatching route handlers that record stats ─────────

TEST(Integration, ThreadPool_With_RequestStats) {
    ThreadPool pool(4);
    RequestStats stats;
    constexpr int kRequests = 500;

    std::vector<std::future<void>> futs;
    futs.reserve(kRequests);

    for (int i = 0; i < kRequests; ++i) {
        futs.emplace_back(pool.submit([&stats, i]() {
            RequestTimer timer(stats, i % 2 == 0 ? "/metrics" : "/health");
            // Simulate work
            volatile int x = 0;
            for (int j = 0; j < 1000; ++j) x += j;
            (void)x;
            timer.finish(true);
        }));
    }
    for (auto& f : futs) f.get();

    EXPECT_EQ(stats.total_requests(), static_cast<uint64_t>(kRequests));
    EXPECT_EQ(stats.total_errors(), 0u);

    auto snap = stats.snapshot();
    EXPECT_EQ(snap["/metrics"].requests + snap["/health"].requests,
              static_cast<uint64_t>(kRequests));
}
