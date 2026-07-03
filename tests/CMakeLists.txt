find_package(GTest REQUIRED)

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

include(GoogleTest)
gtest_discover_tests(test_ebpf_monitor)
