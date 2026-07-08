cmake_minimum_required(VERSION 3.20)
project(ebpf_system_monitor VERSION 1.0.0 LANGUAGES C CXX)

# ── ccache (faster rebuilds) ──────────────────────────────────────────────────
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    set(CMAKE_C_COMPILER_LAUNCHER   "${CCACHE_PROGRAM}")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler flags ────────────────────────────────────────────────────────
add_compile_options(
    -Wall -Wextra -Wpedantic -Wconversion -Werror
    -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)
add_link_options($<$<CONFIG:Debug>:-fsanitize=address,undefined>)

# ── Найти libbpf ─────────────────────────────────────────────────────────
find_library(LIBBPF_LIB bpf REQUIRED)
find_path(LIBBPF_INCLUDE bpf/libbpf.h REQUIRED)

find_library(LIBELF_LIB elf REQUIRED)
find_library(LIBZ_LIB z REQUIRED)

# ── BPF объекты (компилируются clang -target bpf) ────────────────────────
find_program(CLANG clang REQUIRED)
find_program(BPFTOOL bpftool)

set(BPF_SRCS
    bpf/tcp_tracer.bpf.c
    bpf/syscall_audit.bpf.c
    bpf/net_stats.bpf.c
)

# Генерируем vmlinux.h из текущего ядра
if(BPFTOOL)
    set(VMLINUX_H "${CMAKE_BINARY_DIR}/vmlinux.h")
    add_custom_command(
        OUTPUT  ${VMLINUX_H}
        COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
        COMMENT "Generating vmlinux.h from BTF"
        VERBATIM
    )
    add_custom_target(vmlinux_h DEPENDS ${VMLINUX_H})
    set(BPF_VMLINUX_DEP vmlinux_h)
else()
    message(STATUS "bpftool not found — vmlinux.h must be provided at ${CMAKE_BINARY_DIR}/vmlinux.h")
    set(BPF_VMLINUX_DEP "")
endif()

set(BPF_OBJECTS "")
foreach(SRC ${BPF_SRCS})
    get_filename_component(NAME ${SRC} NAME_WE)
    set(OBJ "${CMAKE_BINARY_DIR}/bpf/${NAME}.bpf.o")
    add_custom_command(
        OUTPUT  ${OBJ}
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/bpf"
        COMMAND ${CLANG}
            -target bpf
            -O2 -g
            -I${CMAKE_SOURCE_DIR}/include
            -I${CMAKE_SOURCE_DIR}/bpf
            -I${CMAKE_BINARY_DIR}          # vmlinux.h
            -I${LIBBPF_INCLUDE}
            -D__TARGET_ARCH_x86
            -c ${CMAKE_SOURCE_DIR}/${SRC}
            -o ${OBJ}
        DEPENDS ${CMAKE_SOURCE_DIR}/${SRC} ${BPF_VMLINUX_DEP}
        COMMENT "Compiling BPF: ${SRC}"
        VERBATIM
    )
    list(APPEND BPF_OBJECTS ${OBJ})
endforeach()

add_custom_target(bpf_programs DEPENDS ${BPF_OBJECTS})  # не ALL — требует BPF toolchain

# ── Основной исполняемый файл ─────────────────────────────────────────────
add_executable(ebpf-monitor
    src/monitor.cpp
)

target_include_directories(ebpf-monitor PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/dpdk_sim
    ${CMAKE_SOURCE_DIR}/src/http
    ${LIBBPF_INCLUDE}
)

target_link_libraries(ebpf-monitor PRIVATE
    ${LIBBPF_LIB}
    ${LIBELF_LIB}
    ${LIBZ_LIB}
    pthread
)

if(BPFTOOL)
    add_dependencies(ebpf-monitor bpf_programs)
endif()

# ── Тесты ────────────────────────────────────────────────────────────────
include(CTest)
enable_testing()

find_package(GTest QUIET)
if(GTest_FOUND OR TARGET GTest::gtest)
    add_subdirectory(tests)
endif()

# ── Install ───────────────────────────────────────────────────────────────
install(TARGETS ebpf-monitor RUNTIME DESTINATION bin)
install(FILES ${BPF_OBJECTS} DESTINATION lib/ebpf-monitor)
