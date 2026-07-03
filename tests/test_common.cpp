// tests/test_common.cpp — тесты структур и констант common.h

#include <gtest/gtest.h>
#include "../include/common.h"
#include <cstddef>

TEST(CommonStructs, TcpEventSize)
{
    // Убеждаемся что структура не разбухла от padding
    EXPECT_LE(sizeof(tcp_event), 128u);
}

TEST(CommonStructs, SyscallEventSize)
{
    EXPECT_LE(sizeof(syscall_event), 128u);
}

TEST(CommonStructs, ActionConstants)
{
    EXPECT_EQ(TCP_ACTION_CONNECT, 0);
    EXPECT_EQ(TCP_ACTION_CLOSE,   1);
}

TEST(CommonStructs, TcpEventFieldOffsets)
{
    // timestamp_ns должен быть первым полем (выровнен на 8)
    EXPECT_EQ(offsetof(tcp_event, timestamp_ns), 0u);
    // comm — фиксированный размер 16 байт
    EXPECT_EQ(sizeof(tcp_event::comm), 16u);
}

TEST(CommonStructs, NetStatsKeyPadding)
{
    // Структура используется как BPF map key — должна быть POD без дыр
    EXPECT_EQ(sizeof(net_stats_key), 4u);
}

TEST(CommonStructs, NetStatsValLayout)
{
    EXPECT_EQ(sizeof(net_stats_val), 16u);  // 2 × uint64_t
}
