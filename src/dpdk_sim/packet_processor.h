// src/dpdk_sim/packet_processor.h — Batch packet processor (DPDK burst mode)
//
// Demonstrates DPDK's core performance pattern:
//   1. Dequeue a BURST of packets (e.g. 32) from ring — amortises overhead
//   2. Process each packet in the burst (zero-copy: work with pointers)
//   3. Return processed packets to memory pool
//
// In real DPDK: rte_eth_rx_burst() → process[] → rte_eth_tx_burst()
// Here:         ring.dequeue_burst() → process[] → pool.free_burst()

#pragma once
#include "memory_pool.h"
#include "spsc_ring.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace dpdk_sim {

/// Simulated network packet (mimics DPDK mbuf fields we care about)
struct Packet {
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t  proto{0};      // IPPROTO_TCP=6, IPPROTO_UDP=17
    uint8_t  _pad[3]{};
    uint32_t len{0};        // payload length in bytes
    uint64_t timestamp_ns{0};
    uint8_t  data[64]{};    // payload (zero-copy: normally a pointer to DMA buf)
};

/// Batch size — same as DPDK's typical RX burst size
static constexpr std::size_t BURST_SIZE = 32;

/// Statistics gathered during processing
struct ProcessorStats {
    uint64_t pkts_processed{0};
    uint64_t pkts_dropped{0};   // ring full or pool exhausted
    uint64_t bytes_processed{0};
    uint64_t bursts{0};
};

/// Callback invoked per packet in the burst.
using PacketHandler = std::function<void(Packet* pkt)>;

/// BatchProcessor: dequeues packets from an SPSC ring in bursts,
/// calls handler for each, then returns packets to the memory pool.
template <std::size_t RingSize = 1024, std::size_t PoolSize = 512>
class BatchProcessor {
    static_assert((RingSize & (RingSize - 1)) == 0);
    static_assert((PoolSize & (PoolSize - 1)) == 0);

    SpscRing<Packet*, RingSize>  ring_;       // producer → processor
    MemoryPool<Packet, PoolSize> pool_;       // owns packet objects
    PacketHandler                handler_;
    ProcessorStats               stats_{};

public:
    explicit BatchProcessor(PacketHandler handler)
        : handler_(std::move(handler)) {}

    BatchProcessor(const BatchProcessor&)            = delete;
    BatchProcessor& operator=(const BatchProcessor&) = delete;

    /// Producer-side: send a packet (zero-copy — caller gets ptr from alloc())
    bool send(Packet* pkt) noexcept {
        if (!ring_.enqueue(pkt)) {
            ++stats_.pkts_dropped;
            pool_.free(pkt);   // return to pool on drop
            return false;
        }
        return true;
    }

    /// Allocate a packet from pool (zero-copy: no malloc, just pointer hand-off)
    [[nodiscard]] Packet* alloc_packet() noexcept { return pool_.alloc(); }

    /// Consumer-side: process one burst (up to BURST_SIZE packets).
    /// Returns number of packets processed.
    std::size_t process_burst() noexcept {
        std::array<Packet*, BURST_SIZE> burst{};
        const std::size_t n = ring_.dequeue_burst(burst.data(), BURST_SIZE);
        if (n == 0) return 0;

        for (std::size_t i = 0; i < n; ++i) {
            handler_(burst[i]);
            stats_.bytes_processed += burst[i]->len;
        }
        stats_.pkts_processed += n;
        ++stats_.bursts;

        pool_.free_burst(burst.data(), n);   // batch return — amortised overhead
        return n;
    }

    const ProcessorStats&  stats()      const noexcept { return stats_; }
    const MemoryPool<Packet, PoolSize>& pool() const noexcept { return pool_; }
    bool ring_empty() const noexcept { return ring_.empty(); }
};

} // namespace dpdk_sim
