// src/dpdk_sim/spsc_ring.h — Lock-free SPSC ring buffer
// Inspired by DPDK rte_ring; cache-line aligned to eliminate false sharing.
//
// Constraints:
//   - Single Producer / Single Consumer ONLY
//   - Capacity must be power of 2
//   - T must be trivially copyable
//
// Memory ordering rationale:
//   enqueue: store item, then RELEASE head_ (reader sees item before head update)
//   dequeue: ACQUIRE head_ (see all writes before producer's release), then
//            store item, then RELEASE tail_

#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <type_traits>

namespace dpdk_sim {

template <typename T, std::size_t Capacity>
class SpscRing {
    static_assert((Capacity & (Capacity - 1)) == 0,
                  "Capacity must be a power of 2");
    static_assert(std::is_trivially_copyable_v<T>,
                  "T must be trivially copyable");

    static constexpr std::size_t CACHE_LINE = 64;
    static constexpr std::size_t MASK       = Capacity - 1;

    // Pad head_ and tail_ to separate cache lines — prevents false sharing
    alignas(CACHE_LINE) std::atomic<std::size_t> head_{0};  // written by producer
    alignas(CACHE_LINE) std::atomic<std::size_t> tail_{0};  // written by consumer
    alignas(CACHE_LINE) std::array<T, Capacity>  data_{};

public:
    SpscRing() = default;
    SpscRing(const SpscRing&)            = delete;
    SpscRing& operator=(const SpscRing&) = delete;

    // --- Single-item API ---

    /// Producer: enqueue one item. Returns false if ring is full.
    [[nodiscard]] bool enqueue(const T& item) noexcept {
        const std::size_t h = head_.load(std::memory_order_relaxed);
        const std::size_t t = tail_.load(std::memory_order_acquire);
        if (h - t >= Capacity) return false;  // full
        data_[h & MASK] = item;
        head_.store(h + 1, std::memory_order_release);
        return true;
    }

    /// Consumer: dequeue one item. Returns false if ring is empty.
    [[nodiscard]] bool dequeue(T& item) noexcept {
        const std::size_t t = tail_.load(std::memory_order_relaxed);
        const std::size_t h = head_.load(std::memory_order_acquire);
        if (t == h) return false;  // empty
        item = data_[t & MASK];
        tail_.store(t + 1, std::memory_order_release);
        return true;
    }

    // --- Burst API (DPDK-style) ---

    /// Producer: enqueue up to n items. Returns number actually enqueued.
    [[nodiscard]] std::size_t enqueue_burst(const T* items, std::size_t n) noexcept {
        const std::size_t h    = head_.load(std::memory_order_relaxed);
        const std::size_t t    = tail_.load(std::memory_order_acquire);
        const std::size_t free = Capacity - (h - t);
        const std::size_t cnt  = (n < free) ? n : free;
        for (std::size_t i = 0; i < cnt; ++i)
            data_[(h + i) & MASK] = items[i];
        head_.store(h + cnt, std::memory_order_release);
        return cnt;
    }

    /// Consumer: dequeue up to n items. Returns number actually dequeued.
    [[nodiscard]] std::size_t dequeue_burst(T* items, std::size_t n) noexcept {
        const std::size_t t    = tail_.load(std::memory_order_relaxed);
        const std::size_t h    = head_.load(std::memory_order_acquire);
        const std::size_t avail = h - t;
        const std::size_t cnt   = (n < avail) ? n : avail;
        for (std::size_t i = 0; i < cnt; ++i)
            items[i] = data_[(t + i) & MASK];
        tail_.store(t + cnt, std::memory_order_release);
        return cnt;
    }

    // --- Capacity queries (approximate — race between head/tail reads) ---

    [[nodiscard]] std::size_t size() const noexcept {
        return head_.load(std::memory_order_relaxed) -
               tail_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] bool empty() const noexcept { return size() == 0; }
    [[nodiscard]] bool full()  const noexcept { return size() >= Capacity; }
    [[nodiscard]] static constexpr std::size_t capacity() noexcept { return Capacity; }
};

} // namespace dpdk_sim
