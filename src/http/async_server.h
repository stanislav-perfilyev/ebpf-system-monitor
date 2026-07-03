// src/http/async_server.h — Async HTTP/1.1 server using epoll (edge-triggered)
//
// Demonstrates:
//   - epoll(7) with EPOLLET (edge-triggered) + non-blocking sockets
//   - O(1) event demultiplexing: single epoll_fd watches N client fds
//   - Graceful stop via eventfd
//   - Minimal HTTP/1.1 subset: GET, Connection: close
//
// NOT a production server — demonstrates async I/O patterns for portfolio.

#pragma once
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

namespace http {

/// Handler: receives request path (e.g. "/metrics"), returns HTTP body string.
/// Content-Type is determined by the server based on path prefix.
using RouteHandler = std::function<std::string(std::string_view path)>;

class AsyncHttpServer {
    static constexpr int    MAX_EVENTS = 64;
    static constexpr size_t BUF_SIZE   = 8192;

    int                  listen_fd_{-1};
    int                  epoll_fd_{-1};
    int                  stop_fd_{-1};    // eventfd for graceful stop
    uint16_t             port_{0};
    RouteHandler         handler_;
    std::atomic<bool>    running_{false};

    // Per-client read buffer
    std::unordered_map<int, std::string> read_bufs_;

    static void set_nonblocking(int fd) {
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0) throw std::runtime_error("fcntl F_GETFL failed");
        if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
            throw std::runtime_error("fcntl F_SETFL O_NONBLOCK failed");
    }

    static void epoll_add(int epfd, int fd, uint32_t events) {
        epoll_event ev{};
        ev.events  = events;
        ev.data.fd = fd;
        if (::epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
            throw std::runtime_error(std::string("epoll_ctl ADD: ") + strerror(errno));
    }

    static void epoll_del(int epfd, int fd) {
        ::epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
    }

    void accept_clients() {
        while (true) {
            sockaddr_in addr{};
            socklen_t   len = sizeof(addr);
            int client = ::accept4(listen_fd_,
                                   reinterpret_cast<sockaddr*>(&addr), &len,
                                   SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (client < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;  // drained
                break;
            }
            epoll_add(epoll_fd_, client, EPOLLIN | EPOLLET | EPOLLRDHUP);
        }
    }

    void handle_client(int fd) {
        auto& buf = read_bufs_[fd];
        char  tmp[BUF_SIZE];

        // Edge-triggered: must drain until EAGAIN
        while (true) {
            ssize_t n = ::read(fd, tmp, sizeof(tmp));
            if (n > 0) {
                buf.append(tmp, static_cast<size_t>(n));
                // Heuristic: header ends with \r\n\r\n
                if (buf.find("\r\n\r\n") != std::string::npos) break;
            } else if (n == 0 || errno == ECONNRESET) {
                close_client(fd); return;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                close_client(fd); return;
            }
        }

        // Parse method + path from first line
        const auto path = parse_path(buf);
        const auto body = handler_ ? handler_(path) : "Not Found";

        // Determine content type
        const bool is_metrics = (path == "/metrics");
        const std::string ct  = is_metrics
            ? "text/plain; version=0.0.4; charset=utf-8"
            : "application/json";

        const auto response = build_response(
            path.empty() || body.empty() ? 404 : 200, ct, body);

        // Write (best-effort — non-blocking, partial writes ignored for demo)
        ::write(fd, response.data(), response.size());
        close_client(fd);
    }

    void close_client(int fd) {
        epoll_del(epoll_fd_, fd);
        read_bufs_.erase(fd);
        ::close(fd);
    }

    static std::string parse_path(const std::string& req) {
        // "GET /path HTTP/1.1\r\n..."
        const auto sp1 = req.find(' ');
        if (sp1 == std::string::npos) return "";
        const auto sp2 = req.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) return "";
        return req.substr(sp1 + 1, sp2 - sp1 - 1);
    }

    static std::string build_response(int status,
                                      std::string_view content_type,
                                      std::string_view body) {
        const std::string_view reason = (status == 200) ? "OK" : "Not Found";
        std::string resp;
        resp.reserve(256 + body.size());
        resp  = "HTTP/1.1 ";
        resp += std::to_string(status);
        resp += " ";
        resp += reason;
        resp += "\r\nContent-Type: ";
        resp += content_type;
        resp += "\r\nContent-Length: ";
        resp += std::to_string(body.size());
        resp += "\r\nConnection: close\r\n\r\n";
        resp += body;
        return resp;
    }

public:
    explicit AsyncHttpServer(uint16_t port, RouteHandler handler)
        : port_(port), handler_(std::move(handler)) {}

    ~AsyncHttpServer() { stop(); }

    AsyncHttpServer(const AsyncHttpServer&)            = delete;
    AsyncHttpServer& operator=(const AsyncHttpServer&) = delete;

    /// Start listening and create epoll instance.
    /// Call run() or run_once() to process events.
    void start() {
        // Listen socket
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (listen_fd_ < 0) throw std::runtime_error("socket() failed");

        int opt = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(port_);

        if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
            throw std::runtime_error(std::string("bind() failed: ") + strerror(errno));
        if (::listen(listen_fd_, SOMAXCONN) < 0)
            throw std::runtime_error("listen() failed");

        // epoll
        epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd_ < 0) throw std::runtime_error("epoll_create1() failed");
        epoll_add(epoll_fd_, listen_fd_, EPOLLIN | EPOLLET);

        // stop eventfd
        stop_fd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (stop_fd_ < 0) throw std::runtime_error("eventfd() failed");
        epoll_add(epoll_fd_, stop_fd_, EPOLLIN);

        running_.store(true, std::memory_order_release);
    }

    /// Blocking event loop — call from a dedicated thread.
    void run() {
        std::array<epoll_event, MAX_EVENTS> events{};
        while (running_.load(std::memory_order_acquire)) {
            const int n = ::epoll_wait(epoll_fd_, events.data(),
                                       static_cast<int>(events.size()), 100 /*ms*/);
            for (int i = 0; i < n; ++i) {
                const int fd = events[i].data.fd;
                if (fd == stop_fd_)    { running_ = false; break; }
                if (fd == listen_fd_)  { accept_clients(); }
                else                   { handle_client(fd); }
            }
        }
        if (listen_fd_ >= 0) { ::close(listen_fd_); listen_fd_ = -1; }
        if (epoll_fd_  >= 0) { ::close(epoll_fd_);  epoll_fd_  = -1; }
        if (stop_fd_   >= 0) { ::close(stop_fd_);   stop_fd_   = -1; }
    }

    /// Signal the event loop to exit.
    void stop() noexcept {
        if (stop_fd_ >= 0 && running_.load()) {
            uint64_t v = 1;
            ::write(stop_fd_, &v, sizeof(v));
        }
    }

    [[nodiscard]] bool     is_running() const noexcept { return running_; }
    [[nodiscard]] uint16_t port()        const noexcept { return port_; }
};

} // namespace http
