#pragma once
// ─── src/http/request_stats.h ─────────────────────────────────────────────────
//
// Thread-safe per-route request statistics for the HTTP server.
//
// Read-heavy access pattern:
//   write (record)    → unique_lock — one request finishes per worker thread
//   read  (snapshot)  → shared_lock — Prometheus /stats endpoint, concurrent OK
//
// Stats collected per route:
//   - request count
//   - error count (handler threw)
//   - total latency (µs)
//   - minimum and maximum latency (µs)
//
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace http {

struct RouteStats {
    uint64_t requests{0};
    uint64_t errors{0};
    uint64_t total_us{0};
    uint64_t min_us{std::numeric_limits<uint64_t>::max()};
    uint64_t max_us{0};

    [[nodiscard]] double mean_us() const noexcept {
        return requests > 0 ? static_cast<double>(total_us) / static_cast<double>(requests) : 0.0;
    }
};

class RequestStats {
public:
    // Called from worker thread (exclusive write)
    void record(const std::string& route, uint64_t elapsed_us, bool ok) noexcept {
        std::unique_lock lock(m_mtx);
        auto& s = m_stats[route];
        ++s.requests;
        s.total_us += elapsed_us;
        s.min_us    = std::min(s.min_us, elapsed_us);
        s.max_us    = std::max(s.max_us, elapsed_us);
        if (!ok) ++s.errors;
    }

    // Called from any thread (concurrent readers ok)
    [[nodiscard]] std::unordered_map<std::string, RouteStats> snapshot() const {
        std::shared_lock lock(m_mtx);
        return m_stats;
    }

    [[nodiscard]] uint64_t total_requests() const noexcept {
        std::shared_lock lock(m_mtx);
        uint64_t n = 0;
        for (const auto& [_, s] : m_stats) n += s.requests;
        return n;
    }

    [[nodiscard]] uint64_t total_errors() const noexcept {
        std::shared_lock lock(m_mtx);
        uint64_t n = 0;
        for (const auto& [_, s] : m_stats) n += s.errors;
        return n;
    }

private:
    mutable std::shared_mutex                      m_mtx;
    std::unordered_map<std::string, RouteStats>    m_stats;
};

// ─── RAII request timer ────────────────────────────────────────────────────────
//
// Usage (from a worker thread):
//   RequestTimer timer(stats, "/metrics");
//   // ... handle request ...
//   timer.finish(ok);
//
class RequestTimer {
public:
    RequestTimer(RequestStats& stats, std::string route) noexcept
        : m_stats{stats}
        , m_route{std::move(route)}
        , m_start{std::chrono::steady_clock::now()}
    {}

    void finish(bool ok = true) noexcept {
        if (m_done) return;
        m_done = true;
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - m_start).count();
        m_stats.record(m_route, static_cast<uint64_t>(elapsed), ok);
    }

    ~RequestTimer() { finish(false); }  // error if finish() not called manually

    RequestTimer(const RequestTimer&)            = delete;
    RequestTimer& operator=(const RequestTimer&) = delete;

private:
    RequestStats&                             m_stats;
    std::string                               m_route;
    std::chrono::steady_clock::time_point     m_start;
    bool                                      m_done{false};
};

} // namespace http
