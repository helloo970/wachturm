#pragma once
// Einfacher, aber korrekter Thread-Pool (C++20).
//
// - submit() nimmt eine beliebige Funktion und gibt ein std::future zurueck.
// - Beim Zerstoeren werden ALLE noch wartenden Aufgaben abgearbeitet,
//   danach beenden sich die Threads (std::jthread + stop_token).
//
// WICHTIG: Eine Aufgabe darf NICHT selbst auf eine andere Aufgabe desselben
// Pools warten (future.get() im Worker) - das kann zum Deadlock fuehren,
// wenn alle Worker gleichzeitig warten. Deshalb scannt "audit" die Hosts
// nacheinander und nur die Ports eines Hosts parallel.

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <stop_token>
#include <thread>
#include <type_traits>
#include <vector>

namespace wt {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t threadCount = std::thread::hardware_concurrency()) {
        threadCount = std::max<std::size_t>(1, threadCount);
        workers_.reserve(threadCount);
        for (std::size_t i = 0; i < threadCount; ++i) {
            workers_.emplace_back([this](std::stop_token st) { workerLoop(st); });
        }
    }

    ~ThreadPool() {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        for (auto& w : workers_) w.request_stop();
        cv_.notify_all();
        workers_.clear();  // jthread-Destruktor wartet (join)
    }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    template <class F>
    auto submit(F&& fn) -> std::future<std::invoke_result_t<std::decay_t<F>>> {
        using R = std::invoke_result_t<std::decay_t<F>>;
        // packaged_task ist nicht kopierbar, std::function braucht aber
        // kopierbare Objekte -> ueber shared_ptr einpacken.
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(fn));
        std::future<R> fut = task->get_future();
        {
            std::lock_guard lock(mutex_);
            if (stopping_) throw std::runtime_error("ThreadPool wird bereits beendet");
            queue_.emplace([task] { (*task)(); });
        }
        cv_.notify_one();
        return fut;
    }

    std::size_t size() const noexcept { return workers_.size(); }

private:
    void workerLoop(std::stop_token st) {
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock lock(mutex_);
                // Wartet, bis Arbeit da ist ODER ein Stopp angefordert wurde.
                cv_.wait(lock, st, [this] { return !queue_.empty(); });
                if (queue_.empty()) return;  // Stopp und nichts mehr zu tun
                job = std::move(queue_.front());
                queue_.pop();
            }
            job();  // Exceptions landen im future (packaged_task)
        }
    }

    std::mutex mutex_;
    std::condition_variable_any cv_;
    std::queue<std::function<void()>> queue_;
    bool stopping_ = false;
    // workers_ MUSS als letztes deklariert sein: wird zuerst zerstoert,
    // waehrend mutex_/cv_/queue_ noch leben.
    std::vector<std::jthread> workers_;
};

// Fortschritts-Callback: (erledigt, gesamt)
using ProgressFn = std::function<void(std::size_t, std::size_t)>;

}  // namespace wt
