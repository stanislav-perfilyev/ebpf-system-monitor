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
//   - RAII: destructor sets stop flag, notifies all, joins the workers once
//     they have drained the queue (every submitted task still runs).
//   - submit() is callable from any thread; returns std::future<T>.
//
// Thread-safety model:
//   submit()            → unique_lock on m_mtx (task push + notify_one)
//   worker drain loop  → unique_lock on m_mtx (task pop)
//   size()             → std::atomic (wait-free)
//   completed()        → std::atomic, bumped before the task's future is ready
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
        // Stop all workers: set flag, wake them up; they drain the queue first
        {
            std::unique_lock lock(m_mtx);
            m_stop = true;
        }
        m_cv.notify_all();
        // Join here rather than in the implicit member teardown: members are
        // destroyed in reverse declaration order, so m_stop, m_pending and
        // m_completed (declared after m_workers) would already be dead while
        // workers still finish queued tasks and touch them.
        m_workers.clear();
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
            [this,
             func = std::forward<F>(f),
             ...bound = std::forward<Args>(args)]() mutable {
                CompletionGuard done{m_completed};
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
    /// A task is counted before its future becomes ready, so once get() or
    /// wait() on that future returns, completed() already includes it.
    [[nodiscard]] uint64_t completed() const noexcept {
        return m_completed.load(std::memory_order_relaxed);
    }

private:
    // Bumps the counter when the task body returns or throws — that is, before
    // packaged_task stores the result and makes the future ready. The bump is
    // sequenced before that release, so get() on the future happens-after it.
    struct CompletionGuard {
        std::atomic<uint64_t>& counter;
        ~CompletionGuard() { counter.fetch_add(1, std::memory_order_relaxed); }
    };

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
