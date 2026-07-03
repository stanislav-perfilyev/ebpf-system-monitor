// src/dpdk_sim/memory_pool.h — Fixed-size object pool (DPDK rte_mempool concept)
//
// Mimics DPDK's approach:
//   - Pre-allocated slab of fixed-size objects (no malloc in hot path)
//   - Free-list managed via SpscRing for producer/consumer separation
//   - For multi-threaded use, caller is responsible for access patterns
//     (alloc on one thread, free on another = classic SPSC use case)
//
// NOTE: this is a conceptual demo. Real DPDK uses per-lcore caches +
//       multi-producer/consumer ring. Here we show the principle.

#pragma once
#include "spsc_ring.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <new>

namespace dpdk_sim {

template <typename T, std::size_t PoolSize>
class MemoryPool {
    static_assert((PoolSize & (PoolSize - 1)) == 0,
                  "PoolSize must be a power of 2");

    // Storage: cache-line aligned, avoids false sharing between objects
    static constexpr std::size_t ALIGN = alignof(T) > 64 ? alignof(T) : 64;
    struct alignas(ALIGN) Block { std::byte raw[sizeof(T)]; };

    std::array<Block, PoolSize>   storage_;
    SpscRing<T*, PoolSize>        free_ring_;
    std::size_t                   total_allocs_{0};

public:
    MemoryPool() {
        // Pre-populate free list
        for (std::size_t i = 0; i < PoolSize; ++i)
            (void)free_ring_.enqueue(reinterpret_cast<T*>(&storage_[i]));  // always succeeds: ring_size == pool_size
    }

    ~MemoryPool() = default;
    MemoryPool(const MemoryPool&)            = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;

    /// Allocate an object slot (raw — caller must placement-new if needed).
    /// Returns nullptr when pool is exhausted.
    [[nodiscard]] T* alloc() noexcept {
        T* obj = nullptr;
        if (free_ring_.dequeue(obj)) {
            ++total_allocs_;
            return obj;
        }
        return nullptr;
    }

    /// Return object slot to pool. Object is NOT destroyed — caller's responsibility.
    void free(T* obj) noexcept {
        (void)free_ring_.enqueue(obj);  // free list cannot be full when pool isn't exhausted
    }

    // --- Burst variants (zero-copy batch allocation) ---

    /// Allocate up to n objects. Returns count actually allocated.
    std::size_t alloc_burst(T** objs, std::size_t n) noexcept {
        std::size_t got = 0;
        while (got < n) {
            T* obj = nullptr;
            if (!free_ring_.dequeue(obj)) break;
            objs[got++] = obj;
            ++total_allocs_;
        }
        return got;
    }

    /// Return n objects at once.
    void free_burst(T** objs, std::size_t n) noexcept {
        free_ring_.enqueue_burst(objs, n);
    }

    // --- Stats ---
    [[nodiscard]] std::size_t available()    const noexcept { return free_ring_.size(); }
    [[nodiscard]] std::size_t in_use()       const noexcept { return PoolSize - available(); }
    [[nodiscard]] std::size_t total_allocs() const noexcept { return total_allocs_; }
    [[nodiscard]] static constexpr std::size_t capacity() noexcept { return PoolSize; }
};

} // namespace dpdk_sim
