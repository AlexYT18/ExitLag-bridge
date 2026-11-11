#ifndef EXL_UDP_LIFECYCLE_H
#define EXL_UDP_LIFECYCLE_H
#include <stdint.h>
#include <stddef.h>

/* A scan resumes after a reactor yield; only a complete scan starts the idle
 * interval. The caller bounds expensive notifications separately. */
struct udp_reaper {
    size_t cursor, remaining;
    uint64_t next_due, started, deadline;
    int active;
};
int udp_reaper_begin(struct udp_reaper *state, size_t capacity,
                     uint64_t now_ms, uint64_t budget_ms);
int udp_reaper_next(struct udp_reaper *state, size_t capacity,
                    uint64_t now_ms, size_t *index);
void udp_activity_touch(uint64_t *last_seen_ms, uint64_t now_ms);
uint64_t udp_activity_idle(uint64_t last_seen_ms, uint64_t now_ms);
#endif
