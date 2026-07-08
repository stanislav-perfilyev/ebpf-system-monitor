// src/monitor.cpp — главный демон eBPF System Monitor
//
// Запуск: sudo ./ebpf-monitor [--filter-pid N] [--filter-port N] [--json] [--port N]
// Требует root (CAP_BPF + CAP_SYS_ADMIN) для загрузки BPF программ.
//
// HTTP API (запускается автоматически):
//   GET /metrics      — Prometheus-compatible метрики
//   GET /connections  — топ TCP соединений (JSON)
//   GET /health       — {"status":"ok"}

#include "ebpf_loader.h"
#include "stats_reporter.h"
#include "http/async_server.h"
#include "http/metrics.h"
#include "../include/common.h"

#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cinttypes>
#include <cstring>
#include <getopt.h>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>
#include <thread>
#include <chrono>

/* ── Глобальный флаг остановки ───────────────────────────────────────── */
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int) { g_stop = 1; }

/* ── Ring buffer callback: TCP события ───────────────────────────────── */
static ebpf::StatsReporter *g_reporter = nullptr;
static bool                 g_json     = false;

static int handle_tcp_event(void * /*ctx*/, void *data, size_t /*size*/)
{
    const auto *ev = static_cast<const tcp_event *>(data);
    if (g_reporter) g_reporter->record(*ev);

    if (g_json) {
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ev->src_ip, src, sizeof(src));
        inet_ntop(AF_INET, &ev->dst_ip, dst, sizeof(dst));
        std::printf(
            "{\"ts\":%" PRIu64 ",\"pid\":%u,\"comm\":\"%s\","
            "\"src\":\"%s:%u\",\"dst\":\"%s:%u\","
            "\"action\":%u,\"tx\":%" PRIu64 ",\"rx\":%" PRIu64 "}\n",
            ev->timestamp_ns, ev->pid, ev->comm,
            src, ev->src_port, dst, ev->dst_port,
            ev->action, ev->bytes_tx, ev->bytes_rx);
        std::fflush(stdout);
    }
    return 0;
}

static int handle_syscall_event(void * /*ctx*/, void *data, size_t /*size*/)
{
    const auto *ev = static_cast<const syscall_event *>(data);
    std::fprintf(stderr,
        "[AUDIT] ts=%" PRIu64 " pid=%u uid=%u comm=%s syscall=%ld\n",
        ev->timestamp_ns, ev->pid, ev->uid, ev->comm, ev->syscall_nr);
    return 0;
}

/* ── Утилита: установить фильтр в BPF map ────────────────────────────── */
static void set_filter(bpf_map *map, uint32_t idx, uint32_t val)
{
    if (bpf_map__update_elem(map, &idx, sizeof(idx),
                             &val, sizeof(val), BPF_ANY) != 0)
        std::cerr << "Warning: could not set filter\n";
}

/* ── HTTP route handler ───────────────────────────────────────────────── */
static std::string http_route(std::string_view path,
                               const ebpf::StatsReporter& reporter)
{
    if (path == "/metrics")
        return http::PrometheusMetrics::from_reporter(reporter);

    if (path == "/connections") {
        std::ostringstream out;
        out << "[";
        bool first = true;
        reporter.for_each([&](const ebpf::ConnectionKey& k,
                               const ebpf::ConnectionStats& s) {
            if (!first) out << ",";
            first = false;
            char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
            in_addr sa{}, da{};
            sa.s_addr = k.src_ip; da.s_addr = k.dst_ip;
            inet_ntop(AF_INET, &sa, src, sizeof(src));
            inet_ntop(AF_INET, &da, dst, sizeof(dst));
            out << "{\"comm\":\"" << s.comm
                << "\",\"pid\":" << k.pid
                << ",\"src\":\"" << src << ":" << ntohs(k.src_port)
                << "\",\"dst\":\"" << dst << ":" << ntohs(k.dst_port)
                << "\",\"tx\":" << s.bytes_tx
                << ",\"rx\":" << s.bytes_rx
                << ",\"connects\":" << s.connects << "}";
        });
        out << "]";
        return out.str();
    }

    if (path == "/health")
        return R"({"status":"ok"})";

    return "";  // → 404
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    uint32_t filter_pid  = 0;
    uint32_t filter_port = 0;
    uint16_t http_port   = 9090;  // Prometheus default

    static const option long_opts[] = {
        {"filter-pid",  required_argument, nullptr, 'p'},
        {"filter-port", required_argument, nullptr, 'P'},
        {"port",        required_argument, nullptr, 'o'},
        {"json",        no_argument,       nullptr, 'j'},
        {"help",        no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:P:o:jh", long_opts, nullptr)) != -1) {
        switch (opt) {
        case 'p': filter_pid  = static_cast<uint32_t>(std::stoul(optarg)); break;
        case 'P': filter_port = static_cast<uint32_t>(std::stoul(optarg)); break;
        case 'o': http_port   = static_cast<uint16_t>(std::stoul(optarg)); break;
        case 'j': g_json = true; break;
        case 'h':
            std::cout << "Usage: sudo ebpf-monitor [OPTIONS]\n"
                      << "  --filter-pid N   trace only PID N\n"
                      << "  --filter-port N  trace only port N\n"
                      << "  --port N         HTTP metrics port (default: 9090)\n"
                      << "  --json           emit JSON lines to stdout\n";
            return 0;
        default:
            return 1;
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    try {
        /* ── Загрузить BPF объекты ─────────────────────────────────── */
        ebpf::BpfObject tcp_obj("bpf/tcp_tracer.bpf.o");
        ebpf::BpfObject audit_obj("bpf/syscall_audit.bpf.o");

        if (filter_pid || filter_port) {
            bpf_map *fmap = tcp_obj.find_map("filters");
            if (filter_pid)  set_filter(fmap, 0, filter_pid);
            if (filter_port) set_filter(fmap, 1, filter_port);
        }

        ebpf::BpfLink tcp_connect_link(
            tcp_obj.attach_kprobe("tcp_connect", "trace_tcp_connect"));
        ebpf::BpfLink tcp_close_link(
            tcp_obj.attach_kprobe("tcp_close", "trace_tcp_close"));
        ebpf::BpfLink audit_link(
            audit_obj.attach_tracepoint("raw_syscalls", "sys_enter",
                                         "audit_syscall"));

        /* ── HTTP сервер в отдельном jthread ──────────────────────── */
        ebpf::StatsReporter reporter;
        g_reporter = &reporter;

        http::AsyncHttpServer http_srv(http_port,
            [&reporter](std::string_view path) {
                return http_route(path, reporter);
            });
        http_srv.start();
        std::jthread http_thread([&http_srv]{ http_srv.run(); });

        std::cout << "eBPF monitor running. HTTP metrics at http://localhost:"
                  << http_port << "/metrics\n"
                  << "Endpoints: /metrics  /connections  /health\n"
                  << "Press Ctrl+C to stop.\n";
        if (filter_pid)  std::cout << "  Filtering PID:  " << filter_pid  << "\n";
        if (filter_port) std::cout << "  Filtering Port: " << filter_port << "\n";

        /* ── Ring buffers ──────────────────────────────────────────── */
        ebpf::BpfRingBuffer tcp_rb(tcp_obj.find_map("tcp_events"),
                                    handle_tcp_event, nullptr);
        ebpf::BpfRingBuffer audit_rb(audit_obj.find_map("syscall_events"),
                                      handle_syscall_event, nullptr);

        /* ── Главный цикл ──────────────────────────────────────────── */
        auto last_print = std::chrono::steady_clock::now();

        while (!g_stop) {
            (void)tcp_rb.poll(100);
            (void)audit_rb.poll(10);

            auto now = std::chrono::steady_clock::now();
            if (!g_json &&
                std::chrono::duration_cast<std::chrono::seconds>(
                    now - last_print).count() >= 5)
            {
                reporter.print_top(10);
                last_print = now;
            }
        }

        std::cout << "\nShutting down.\n";
        http_srv.stop();
        g_reporter = nullptr;

    } catch (const ebpf::Error& e) {
        std::cerr << "eBPF error: " << e.what() << "\n";
        std::cerr << "Tip: run as root (sudo) and ensure BTF is available\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
