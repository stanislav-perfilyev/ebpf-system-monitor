#pragma once
// ─── src/http/thread_pool.h ───────────────────────────────────────────────────
//
// Fixed-size thread pool for dispatching HTTP request handlers off the epoll
// thread. The epoll loop stays fast (I/O only); handler logic (DB lookups,
// metric serialisation) runs on worker threads.
//
// Design:
//   - N std::jthread workers consume tasks from a shared deque.
//   - std::condition_variable wakes workers on new tasks or shutdown.
//   - RAII: destructor sets stop flag, notifies all, jthreads auto-join.
//   - submit() is callable from any thread; returns std::future<T>.
//
// Thread-safety model:
//   submit()            → unique_lock on m_mtx (task push + notify_one)
//   worker drain loop  → unique_lock on m_mtx (task pop)
//   size()             → std::atomic (wait-free)
//
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>

namespace http {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t thread_count = std::thread::hardware_concurrency()) {
        if (thread_count == 0) thread_count = 1;
        m_workers.reserve(thread_count);
        for (std::size_t i = 0; i < thread_count; ++i) {
            m_workers.emplace_back([this](std::stop_token st) {
                worker_loop(st);
            });
        }
    }

    ~ThreadPool() {
        // Stop all workers: set flag, wake them up, jthreads auto-join
        {
            std::unique_lock lock(m_mtx);
            m_stop = true;
        }
        m_cv.notify_all();
        // std::jthread destructor requests stop and joins
    }

    ThreadPool(const ThreadPool&)            = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /// Submit a callable and return a future for its result.
    /// Safe to call from multiple threads simultaneously.
    template<typename F, typename... Args>
    [[nodiscard]] auto submit(F&& f, Args&&... args)
        -> std::future<std::invoke_result_t<F, Args...>> {
        using R = std::invoke_result_t<F, Args...>;

        auto task = std::make_shared<std::packaged_task<R()>>(
            [func = std::forward<F>(f),
             ...bound = std::forward<Args>(args)]() mutable {
                return func(std::forward<Args>(bound)...);
            });

        std::future<R> fut = task->get_future();

        {
            std::unique_lock lock(m_mtx);
            if (m_stop) throw std::runtime_error("ThreadPool: submit after shutdown");
            m_tasks.emplace_back([t = std::move(task)]() { (*t)(); });
            ++m_pending;
        }
        m_cv.notify_one();
        return fut;
    }

    /// Number of workers.
    [[nodiscard]] std::size_t size() const noexcept { return m_workers.size(); }

    /// Approximate number of tasks still in the queue.
    [[nodiscard]] std::size_t pending() const noexcept {
        return m_pending.load(std::memory_order_relaxed);
    }

    /// Total tasks completed since construction (wait-free).
    [[nodiscard]] uint64_t completed() const noexcept {
        return m_completed.load(std::memory_order_relaxed);
    }

private:
    void worker_loop([[maybe_unused]] const std::stop_token& st) {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock lock(m_mtx);
                m_cv.wait(lock, [&] { return m_stop || !m_tasks.empty(); });
                if (m_stop && m_tasks.empty()) return;
                task = std::move(m_tasks.front());
                m_tasks.pop_front();
                --m_pending;
            }
            task();
            m_completed.fetch_add(1, std::memory_order_relaxed);
        }
    }

    std::mutex                        m_mtx;
    std::condition_variable           m_cv;
    std::deque<std::function<void()>> m_tasks;
    std::vector<std::jthread>         m_workers;
    bool                              m_stop{false};
    std::atomic<std::size_t>          m_pending{0};
    std::atomic<uint64_t>             m_completed{0};
};

} // namespace http
