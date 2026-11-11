// Freestanding, bounded PID-domain registry used by the PE shim and native tests.
#ifndef EXITLAG_SHIM_PID_DOMAIN_H
#define EXITLAG_SHIM_PID_DOMAIN_H

namespace exl_pid_domain {

typedef unsigned int u32;
typedef unsigned long long u64;
static_assert(sizeof(u32) == 4 && sizeof(u64) == 8, "PID registry integer widths changed");
static_assert(__atomic_always_lock_free(8, 0), "PID registry requires lock-free x64 atomics");

enum pid_origin : unsigned int {
    pid_unknown = 0, pid_linux = 1, pid_windows = 2, pid_ambiguous = 3
};
enum { capacity = 256 };

// Zero-initialized POD, with no CRT constructor. A slot holds PID<<2 plus the
// observed domain bits. PID zero denotes an empty slot. Atomic publication keeps
// SDK name queries safe while callbacks record owners; no callback lock is held.
struct alignas(8) registry { u64 slots[capacity]; };

static inline unsigned int first_slot(u32 pid)
{
    return (pid * 2654435761u) & (capacity - 1);
}

static inline pid_origin lookup_pid(const registry &values, u32 pid)
{
    if (!pid) return pid_unknown;
    unsigned int slot = first_slot(pid);
    for (unsigned int examined = 0; examined < capacity; ++examined) {
        u64 value = __atomic_load_n(&values.slots[slot], __ATOMIC_ACQUIRE);
        if (!value) return pid_unknown;
        if ((value >> 2) == pid) return (pid_origin)(value & 3);
        slot = (slot + 1) & (capacity - 1);
    }
    return pid_unknown;
}

// A PID seen in both domains remains ambiguous forever. No entry is evicted:
// once full, registering a new PID fails closed while existing entries retain
// their domains. Do not reset while SDK calls/workers may still use old PIDs.
// Saturation and old-PID ambiguity can therefore disable later callbacks until
// the DLL is unloaded; generation-safe reset awaits the worker lifecycle work.
static inline bool remember_pid(registry &values, u32 pid, pid_origin domain)
{
    if (!pid || (domain != pid_linux && domain != pid_windows)) return false;
    const u64 desired = ((u64)pid << 2) | (u64)domain;
    unsigned int slot = first_slot(pid);
    for (unsigned int examined = 0; examined < capacity; ++examined) {
        u64 value = __atomic_load_n(&values.slots[slot], __ATOMIC_ACQUIRE);
        if (!value) {
            if (__atomic_compare_exchange_n(&values.slots[slot], &value, desired, false,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return true;
            // An insertion won this empty slot. Inspect its PID before probing
            // further, so simultaneous registrations cannot create duplicates.
        }
        if ((value >> 2) == pid) {
            u64 observed = __atomic_fetch_or(&values.slots[slot], (u64)domain,
                                             __ATOMIC_ACQ_REL);
            return ((observed | (u64)domain) & 3) == (u64)domain;
        }
        slot = (slot + 1) & (capacity - 1);
    }
    return false;
}

} // namespace exl_pid_domain

#endif // EXITLAG_SHIM_PID_DOMAIN_H
