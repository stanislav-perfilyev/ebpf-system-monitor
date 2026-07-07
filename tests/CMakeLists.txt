find_package(GTest REQUIRED)

# ── Session 1: StatsReporter + common structs ─────────────────────────────
add_executable(test_ebpf_monitor
    test_stats_reporter.cpp
    test_common.cpp
)

target_include_directories(test_ebpf_monitor PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(test_ebpf_monitor PRIVATE
    GTest::gtest
    GTest::gtest_main
    pthread
)

# ── Session 2: DPDK-sim (SpscRing + MemoryPool + BatchProcessor) ──────────
add_executable(test_dpdk_sim
    test_dpdk_sim.cpp
)

target_include_directories(test_dpdk_sim PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/dpdk_sim
)

target_link_libraries(test_dpdk_sim PRIVATE
    GTest::gtest
    GTest::gtest_main
    pthread
)

# ── Session 2: HTTP utilities (Prometheus format + StatsReporter::for_each)
add_executable(test_http
    test_http.cpp
)

target_include_directories(test_http PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/dpdk_sim
    ${CMAKE_SOURCE_DIR}/src/http
)

target_link_libraries(test_http PRIVATE
    GTest::gtest
    GTest::gtest_main
    pthread
)

include(GoogleTest)
gtest_discover_tests(test_ebpf_monitor)
gtest_discover_tests(test_dpdk_sim)
gtest_discover_tests(test_http)

# ── MT demo: ThreadPool + RequestStats ────────────────────────────────────────
add_executable(test_thread_pool
    test_thread_pool.cpp
)

target_include_directories(test_thread_pool PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/http
)

target_link_libraries(test_thread_pool PRIVATE
    GTest::gtest
    GTest::gtest_main
    pthread
)

gtest_discover_tests(test_thread_pool)
