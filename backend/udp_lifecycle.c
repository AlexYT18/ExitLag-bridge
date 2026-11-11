#include "udp_lifecycle.h"
#include <stdint.h>

int udp_reaper_begin(struct udp_reaper *state, size_t capacity,
                     uint64_t now, uint64_t budget)
{
    if (!state || !capacity || !budget || now > UINT64_MAX - budget) return 0;
    if (!state->active) {
        if (now < state->next_due) return 0;
        state->remaining = capacity;
        state->active = 1;
    }
    if (state->cursor >= capacity || state->remaining > capacity) return 0;
    state->started = now;
    state->deadline = now + budget;
    return 1;
}

int udp_reaper_next(struct udp_reaper *state, size_t capacity,
                    uint64_t now, size_t *index)
{
    if (!state || !index || !capacity || !state->active ||
        state->cursor >= capacity || state->remaining > capacity) return 0;
    if (!state->remaining) {
        state->active = 0;
        state->next_due = now > UINT64_MAX - 1000 ? UINT64_MAX : now + 1000;
        return 0;
    }
    if (now < state->started || now >= state->deadline) return 0;
    *index = state->cursor;
    state->cursor = (state->cursor + 1) % capacity;
    --state->remaining;
    return 1;
}

void udp_activity_touch(uint64_t *last_seen, uint64_t now)
{
    if (last_seen) *last_seen = now;
}

uint64_t udp_activity_idle(uint64_t last_seen, uint64_t now)
{
    /* A broken monotonic clock must not retain stale state indefinitely. */
    return now >= last_seen ? now - last_seen : UINT64_MAX;
}
