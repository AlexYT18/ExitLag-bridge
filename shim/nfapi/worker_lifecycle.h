#ifndef EXL_WORKER_LIFECYCLE_H
#define EXL_WORKER_LIFECYCLE_H

// Freestanding lifecycle coordinator. Hooks start/revoke/reap/finished/on_worker
// run under the short gate; join and pause never do. Worker callbacks can revoke
// their own session, but an external caller must reap them before reinitializing.
namespace exl_worker_lifecycle {
enum phase { idle, starting, active, stopping };
struct state {
    volatile long gate;
    phase current;
    bool joining;
    unsigned long long generation;
    unsigned long long completed;
};
template<class Hooks> void lock(state &s, Hooks &h) {
    while (__atomic_exchange_n(&s.gate, 1, __ATOMIC_ACQUIRE)) h.pause();
}
inline void unlock(state &s) { __atomic_store_n(&s.gate, 0, __ATOMIC_RELEASE); }

template<class Hooks> void stop(state &s, Hooks &h) {
    lock(s, h);
    if (s.current == idle) { unlock(s); return; }
    h.revoke();
    s.current = stopping;
    const unsigned long long generation = s.generation;
    if (h.on_worker()) { unlock(s); return; }
    if (s.joining) {
        unlock(s);
        while (__atomic_load_n(&s.completed, __ATOMIC_ACQUIRE) < generation) h.pause();
        return;
    }
    s.joining = true;
    unlock(s);
    // No gate is held here: callbacks may call stop/start without deadlocking.
    h.join();
    lock(s, h);
    h.reap();
    s.joining = false;
    s.current = idle;
    __atomic_store_n(&s.completed, generation, __ATOMIC_RELEASE);
    unlock(s);
}

template<class Hooks> bool start(state &s, Hooks &h) {
    lock(s, h);
    if (s.current == stopping && !s.joining && h.finished()) {
        h.reap();
        s.current = idle;
        __atomic_store_n(&s.completed, s.generation, __ATOMIC_RELEASE);
    }
    if (s.current != idle) { unlock(s); return false; }
    ++s.generation;
    s.current = starting;
    bool ok = h.start();
    s.current = ok ? active : stopping;
    unlock(s);
    if (!ok) stop(s, h);
    return ok;
}
} // namespace exl_worker_lifecycle
#endif
