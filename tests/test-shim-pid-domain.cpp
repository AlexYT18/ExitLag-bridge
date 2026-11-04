// Exercise the production registry without Wine, Windows headers or networking.
#include "../shim/nfapi/pid_domain.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

namespace domain = exl_pid_domain;
static unsigned int checks;

static void require(bool condition, const char *message)
{
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

// A thread gate permits insertion/lookup races without sleeps or timing limits.
struct StartGate {
    std::atomic<unsigned int> ready;
    std::atomic<bool> go;
    StartGate() : ready(0), go(false) {}
    void arrive()
    {
        ready.fetch_add(1, std::memory_order_release);
        while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
    }
    void open(unsigned int count)
    {
        while (ready.load(std::memory_order_acquire) != count) std::this_thread::yield();
        go.store(true, std::memory_order_release);
    }
};

static unsigned int colliding_pid(unsigned int index)
{
    // All of these have the same low byte and share the declared table hash.
    return 1 + index * 256;
}

static void validation_and_identity_tests()
{
    domain::registry r = {};
    require(domain::capacity == 256, "PID domain registry capacity changed");
    require(domain::lookup_pid(r, 0) == domain::pid_unknown, "PID0 acquired an origin");
    require(!domain::remember_pid(r, 0, domain::pid_linux), "Linux PID0 registration accepted");
    require(!domain::remember_pid(r, 0, domain::pid_windows), "Windows PID0 registration accepted");
    for (domain::pid_origin invalid : {domain::pid_unknown, domain::pid_ambiguous,
                                      static_cast<domain::pid_origin>(999)}) {
        require(!domain::remember_pid(r, 77, invalid), "invalid origin registration accepted");
        require(domain::lookup_pid(r, 77) == domain::pid_unknown,
                "invalid origin registration changed registry");
    }
    require(domain::remember_pid(r, 77, domain::pid_linux), "Linux PID registration failed");
    require(domain::remember_pid(r, 77, domain::pid_linux), "same-domain registration failed");
    require(domain::lookup_pid(r, 77) == domain::pid_linux, "Linux origin was not retained");
    require(domain::remember_pid(r, 78, domain::pid_windows), "Windows PID registration failed");
    require(domain::lookup_pid(r, 78) == domain::pid_windows, "Windows origin was not retained");
    require(!domain::remember_pid(r, 77, domain::pid_windows), "cross-domain conflict accepted");
    require(domain::lookup_pid(r, 77) == domain::pid_ambiguous, "conflict did not become ambiguous");
    require(!domain::remember_pid(r, 77, domain::pid_linux), "ambiguous PID reverted to Linux");
    require(!domain::remember_pid(r, 77, domain::pid_windows), "ambiguous PID reverted to Windows");
    require(domain::lookup_pid(r, 77) == domain::pid_ambiguous, "ambiguity was not sticky");
    require(domain::lookup_pid(r, 78) == domain::pid_windows, "conflict changed another PID");

    // Values above bit30 catch truncating a PID before shifting its two tags.
    const unsigned int pids[] = {1, 0x40000001u, 0x80000001u, 0xc0000001u, 0xffffffffu};
    for (unsigned int pid : pids)
        require(domain::remember_pid(r, pid, domain::pid_windows), "full-width PID registration failed");
    for (unsigned int pid : pids)
        require(domain::lookup_pid(r, pid) == domain::pid_windows,
                "full-width PID was truncated or collided with another identity");
    require(domain::lookup_pid(r, 0x7fffffffu) == domain::pid_unknown,
            "unregistered full-width PID aliased a registered PID");
}

static void collision_and_capacity_tests()
{
    domain::registry r = {};
    for (unsigned int i = 0; i < 256; ++i) {
        const domain::pid_origin origin = i % 2 ? domain::pid_linux : domain::pid_windows;
        require(domain::remember_pid(r, colliding_pid(i), origin),
                "collision chain failed before capacity");
    }
    for (unsigned int i = 0; i < 256; ++i)
        require(domain::lookup_pid(r, colliding_pid(i)) ==
                    (i % 2 ? domain::pid_linux : domain::pid_windows),
                "collision chain lookup lost a PID");
    require(!domain::remember_pid(r, colliding_pid(256), domain::pid_linux),
            "full registry accepted an unknown PID");
    require(domain::lookup_pid(r, colliding_pid(256)) == domain::pid_unknown,
            "full registry fabricated an origin for rejected PID");
    require(domain::remember_pid(r, colliding_pid(255), domain::pid_linux),
            "full registry refused same-domain existing PID");
    require(!domain::remember_pid(r, colliding_pid(255), domain::pid_windows),
            "full registry accepted conflicting existing PID");
    require(domain::lookup_pid(r, colliding_pid(255)) == domain::pid_ambiguous,
            "full registry failed to retain existing-PID ambiguity");
    for (unsigned int i = 256; i < 512; ++i)
        require(!domain::remember_pid(r, colliding_pid(i), domain::pid_linux),
                "repeated full-table insert evicted an existing PID");
    for (unsigned int i = 0; i < 255; ++i)
        require(domain::lookup_pid(r, colliding_pid(i)) ==
                    (i % 2 ? domain::pid_linux : domain::pid_windows),
                "capacity failures changed a previous PID");
}

static void concurrent_same_pid_test()
{
    domain::registry r = {};
    StartGate gate;
    std::atomic<bool> valid(true);
    std::vector<std::thread> threads;
    for (unsigned int t = 0; t < 8; ++t)
        threads.emplace_back([&] {
            gate.arrive();
            for (unsigned int n = 0; n < 1000; ++n)
                if (!domain::remember_pid(r, 0xf00000ffu, domain::pid_windows) ||
                    domain::lookup_pid(r, 0xf00000ffu) != domain::pid_windows)
                    valid.store(false, std::memory_order_relaxed);
        });
    gate.open(8);
    for (std::thread &thread : threads) thread.join();
    require(valid.load(), "concurrent same-domain registrations disagreed");
    require(domain::lookup_pid(r, 0xf00000ffu) == domain::pid_windows,
            "concurrent same-domain final origin incorrect");
    // Simultaneous duplicate registrations must occupy only one slot.
    for (unsigned int n = 0; n < 255; ++n)
        require(domain::remember_pid(r, colliding_pid(n), domain::pid_linux),
                "concurrent duplicate registration consumed extra slots");
    require(!domain::remember_pid(r, colliding_pid(255), domain::pid_linux),
            "duplicate test did not fill exactly one slot per PID");
}

static void concurrent_colliding_pids_test()
{
    domain::registry r = {};
    StartGate gate;
    std::atomic<bool> valid(true);
    std::vector<std::thread> threads;
    for (unsigned int t = 0; t < 8; ++t)
        threads.emplace_back([&, t] {
            gate.arrive();
            for (unsigned int n = 0; n < 32; ++n) {
                const unsigned int index = t * 32 + n;
                const domain::pid_origin origin = index % 2 ? domain::pid_linux : domain::pid_windows;
                if (!domain::remember_pid(r, colliding_pid(index), origin))
                    valid.store(false, std::memory_order_relaxed);
            }
        });
    gate.open(8);
    for (std::thread &thread : threads) thread.join();
    require(valid.load(), "concurrent collision insertion lost available capacity");
    for (unsigned int i = 0; i < 256; ++i)
        require(domain::lookup_pid(r, colliding_pid(i)) ==
                    (i % 2 ? domain::pid_linux : domain::pid_windows),
                "concurrent colliding PID acquired wrong origin");
    require(!domain::remember_pid(r, colliding_pid(256), domain::pid_windows),
            "concurrent collision insertion did not preserve exact capacity");
}

static void concurrent_conflict_tests()
{
    for (unsigned int round = 0; round < 16; ++round) {
        domain::registry r = {};
        StartGate gate;
        std::atomic<unsigned int> accepted(0), rejected(0);
        std::vector<std::thread> threads;
        for (unsigned int t = 0; t < 8; ++t)
            threads.emplace_back([&, t] {
                gate.arrive();
                const domain::pid_origin origin = t % 2 ? domain::pid_linux : domain::pid_windows;
                for (unsigned int n = 0; n < 64; ++n) {
                    if (domain::remember_pid(r, 0xffffffffu, origin))
                        accepted.fetch_add(1, std::memory_order_relaxed);
                    else rejected.fetch_add(1, std::memory_order_relaxed);
                }
            });
        gate.open(8);
        for (std::thread &thread : threads) thread.join();
        require(accepted.load() != 0 && rejected.load() != 0,
                "cross-domain race did not observe both acceptance and rejection");
        require(domain::lookup_pid(r, 0xffffffffu) == domain::pid_ambiguous,
                "cross-domain race lost sticky ambiguity");
        require(!domain::remember_pid(r, 0xffffffffu, domain::pid_linux) &&
                !domain::remember_pid(r, 0xffffffffu, domain::pid_windows),
                "cross-domain race allowed ambiguity to resolve later");
    }
}

static void concurrent_lookup_test()
{
    domain::registry r = {};
    StartGate gate;
    std::atomic<unsigned int> writers_done(0);
    std::atomic<bool> valid(true);
    std::atomic<unsigned int> samples(0);
    std::vector<std::thread> threads;
    for (unsigned int t = 0; t < 2; ++t)
        threads.emplace_back([&, t] {
            gate.arrive();
            for (unsigned int n = 0; n < 128; ++n)
                if (!domain::remember_pid(r, colliding_pid(t * 128 + n), domain::pid_linux))
                    valid.store(false, std::memory_order_relaxed);
            writers_done.fetch_add(1, std::memory_order_release);
        });
    for (unsigned int t = 0; t < 4; ++t)
        threads.emplace_back([&, t] {
            gate.arrive();
            do {
                for (unsigned int n = 0; n < 256; ++n) {
                    const domain::pid_origin origin = domain::lookup_pid(r, colliding_pid((n + t) % 256));
                    if (origin != domain::pid_unknown && origin != domain::pid_linux)
                        valid.store(false, std::memory_order_relaxed);
                }
                samples.fetch_add(256, std::memory_order_relaxed);
            } while (writers_done.load(std::memory_order_acquire) != 2);
        });
    gate.open(6);
    for (std::thread &thread : threads) thread.join();
    require(valid.load(), "lookup during insertion observed an invalid or fabricated origin");
    require(samples.load() >= 1024, "concurrent lookup workers did not sample the registry");
    for (unsigned int i = 0; i < 256; ++i)
        require(domain::lookup_pid(r, colliding_pid(i)) == domain::pid_linux,
                "lookup after concurrent insertion lost final origin");
}

int main()
{
    validation_and_identity_tests();
    collision_and_capacity_tests();
    concurrent_same_pid_test();
    concurrent_colliding_pids_test();
    concurrent_conflict_tests();
    concurrent_lookup_test();
    std::printf("PASS: shim PID domains (%u assertions)\n", checks);
}
