// Exercise the production freestanding coordinator with actual native threads.
#include "../shim/nfapi/worker_lifecycle.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>

using namespace exl_worker_lifecycle;
static std::atomic<unsigned> checks(0);
#define CHECK(x) do { assert(x); ++checks; } while (0)

struct test_hooks;
static thread_local test_hooks *active_worker;

struct test_hooks {
    state &lifecycle;
    std::thread workers[2];
    std::atomic<bool> running, done[2], release, callback_stop, callback_done;
    std::atomic<bool> worker_start_result, callback_on_exit;
    std::atomic<unsigned> starts, reaps, joins, revokes;
    unsigned requested_workers;
    bool fail_start;
    explicit test_hooks(state &s) : lifecycle(s), running(false), release(true),
        callback_stop(false), callback_done(false), worker_start_result(true), callback_on_exit(false),
        starts(0), reaps(0), joins(0), revokes(0), requested_workers(2), fail_start(false) {
        done[0] = true; done[1] = true;
    }
    void pause() { std::this_thread::yield(); }
    bool start() {
        ++starts;
        running = true;
        for (unsigned i = 0; i < requested_workers; ++i) {
            done[i] = false;
            workers[i] = std::thread([this, i]() {
                active_worker = this;
                while (running.load()) {
                    if (i == 0 && callback_stop.exchange(false)) {
                        exl_worker_lifecycle::stop(lifecycle, *this);
                        worker_start_result = exl_worker_lifecycle::start(lifecycle, *this);
                        callback_done = true;
                    }
                    pause();
                }
                if (i == 0 && callback_on_exit.load()) {
                    exl_worker_lifecycle::stop(lifecycle, *this);
                    worker_start_result = exl_worker_lifecycle::start(lifecycle, *this);
                    callback_done = true;
                }
                while (!release.load()) pause();
                active_worker = 0;
                done[i] = true;
            });
        }
        return !fail_start;
    }
    void revoke() { ++revokes; running = false; }
    bool on_worker() { return active_worker == this; }
    bool finished() { return done[0].load() && done[1].load(); }
    void join() {
        ++joins;
        for (unsigned i = 0; i < 2; ++i) if (workers[i].joinable()) workers[i].join();
    }
    void reap() {
        // The Windows implementation closes already-signaled HANDLEs. Native
        // std::thread needs a join even in the zero-wait automatic reap path.
        for (unsigned i = 0; i < 2; ++i) {
            if (workers[i].joinable()) {
                CHECK(done[i].load());
                workers[i].join();
            }
        }
        ++reaps;
    }
};

template<class Predicate> static void wait_for(Predicate p) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!p()) { assert(std::chrono::steady_clock::now() < deadline); std::this_thread::yield(); }
}

int main() {
    {
        state s = {}; test_hooks h(s); h.requested_workers = 0;
        stop(s, h); CHECK(h.revokes == 0);
        CHECK(start(s, h)); CHECK(!start(s, h)); CHECK(h.starts == 1);
        stop(s, h); CHECK(s.current == idle); CHECK(h.reaps == 1);
        stop(s, h); CHECK(h.reaps == 1);
    }
    {
        state s = {}; test_hooks h(s); h.requested_workers = 1; h.fail_start = true;
        CHECK(!start(s, h)); CHECK(s.current == idle); CHECK(h.joins == 1); CHECK(h.reaps == 1);
        h.fail_start = false; CHECK(start(s, h)); stop(s, h); CHECK(h.reaps == 2);
    }
    {
        state s = {}; test_hooks h(s); h.release = false;
        CHECK(start(s, h));
        h.callback_stop = true;
        wait_for([&]() { return h.callback_done.load(); });
        CHECK(!h.worker_start_result); CHECK(h.joins == 0); CHECK(!start(s, h));
        std::atomic<bool> stopped(false), second_stopped(false);
        std::thread stopper([&]() { stop(s, h); stopped = true; });
        wait_for([&]() { return h.joins.load() == 1; });
        std::thread second([&]() { stop(s, h); second_stopped = true; });
        wait_for([&]() { return h.revokes.load() >= 3; });
        CHECK(!stopped); CHECK(!second_stopped); CHECK(!start(s, h));
        h.release = true;
        stopper.join(); second.join();
        CHECK(stopped); CHECK(second_stopped); CHECK(h.joins == 1); CHECK(h.reaps == 1);
        CHECK(start(s, h)); stop(s, h);
    }
    {
        state s = {}; test_hooks h(s);
        CHECK(start(s, h)); h.callback_stop = true;
        wait_for([&]() { return h.callback_done.load() && h.finished(); });
        CHECK(h.joins == 0); CHECK(h.reaps == 0);
        CHECK(start(s, h)); CHECK(h.reaps == 1); // finished deferred workers reaped
        stop(s, h); CHECK(h.reaps == 2);
    }
    {
        state s = {}; test_hooks h(s);
        for (unsigned i = 0; i < 100; ++i) { CHECK(start(s, h)); stop(s, h); CHECK(s.current == idle); }
        CHECK(h.starts == 100); CHECK(h.reaps == 100); CHECK(s.completed == 100);
    }
    {
        state s = {}; test_hooks h(s); h.callback_on_exit = true;
        CHECK(start(s, h));
        stop(s, h); // join must allow the exiting callback to reenter APIs
        CHECK(h.callback_done); CHECK(!h.worker_start_result); CHECK(h.reaps == 1);
    }
    {
        state s = {}; test_hooks h(s);
        std::atomic<unsigned> accepted(0);
        std::thread callers[16];
        for (unsigned i = 0; i < 16; ++i)
            callers[i] = std::thread([&]() { if (start(s, h)) ++accepted; });
        for (unsigned i = 0; i < 16; ++i) callers[i].join();
        CHECK(accepted == 1); CHECK(h.starts == 1);
        stop(s, h); CHECK(h.reaps == 1);
    }
    std::printf("PASS: shim worker lifecycle (%u assertions, real native threads)\n", checks.load());
}
