# eBPF System Monitor

Linux system monitor using eBPF — traces TCP connections, audits suspicious syscalls,
and collects per-protocol network statistics. Written in C (BPF kernel side) + C++20 (userspace).

## Features

- **TCP Tracer** — kprobe on `tcp_connect`/`tcp_close` → pid, comm, src/dst IP:port, bytes TX/RX
- **Syscall Auditor** — tracepoint `sys_enter` → alert on execve, ptrace, process_vm_read/write
- **XDP Net Stats** — per-protocol packet/byte counts (TCP, UDP, ICMP, ...) via XDP
- **Live Dashboard** — top-10 connections by traffic, refreshed every 5 seconds
- **Filters** — `--filter-pid`, `--filter-port`
- **JSON output** — `--json` for piping to jq/Elasticsearch

## Requirements

| Tool | Version |
|------|---------|
| Linux kernel | 5.15+ (BTF enabled) |
| clang | 14+ |
| libbpf-dev | 0.7+ |
| cmake | 3.20+ |
| bpftool | any recent |

## Build (WSL2 / Ubuntu 22.04+)

```bash
# Install dependencies (once)
sudo apt install clang libbpf-dev libelf-dev cmake build-essential bpftool

# Build
make build

# Run (requires root for BPF loading)
sudo ./build/ebpf-monitor

# Filter by port
sudo ./build/ebpf-monitor --filter-port 443

# JSON output (pipe to jq)
sudo ./build/ebpf-monitor --json | jq .
```

## Run unit tests (no root required)

```bash
make test
```

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Kernel space                       │
│                                                       │
│  tcp_connect() ──kprobe──► tcp_tracer.bpf            │
│  tcp_close()   ──kprobe──►     │                     │
│                                │ ring buffer          │
│  sys_enter ──tracepoint──► syscall_audit.bpf          │
│                                │ ring buffer          │
│  NIC/lo ─────────XDP──────► net_stats.bpf            │
│                                │ percpu map           │
└────────────────────────────────┼─────────────────────┘
                                 │ libbpf
┌────────────────────────────────▼─────────────────────┐
│                   Userspace (C++20)                   │
│                                                       │
│  BpfObject (RAII)  BpfRingBuffer    StatsReporter     │
│       │                 │                 │            │
│       └────────────────►│────────────────►│            │
│                         │  epoll poll     │            │
│                                      print_top(10)    │
└──────────────────────────────────────────────────────┘
```

## BPF Programs

| File | Type | Hook | Purpose |
|------|------|------|---------|
| `tcp_tracer.bpf.c` | kprobe | `tcp_connect`, `tcp_close` | TCP connection tracking |
| `syscall_audit.bpf.c` | tracepoint | `raw_syscalls/sys_enter` | Suspicious syscall detection |
| `net_stats.bpf.c` | XDP | network interface | Per-protocol statistics |

## Skills Demonstrated

- eBPF CO-RE (Compile Once — Run Everywhere) with BTF
- `BPF_MAP_TYPE_RINGBUF` for efficient kernel→user event streaming
- `kprobe` and `tracepoint` program types
- XDP for zero-copy packet processing
- C++20 RAII wrappers over libbpf C API
- `epoll` async polling of multiple ring buffers
- Thread-safe aggregation with `std::mutex`
