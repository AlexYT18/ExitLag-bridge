#include "../backend/udp_lifecycle.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void activity(void)
{
    uint64_t seen = 1000;
    assert(udp_activity_idle(seen, 60999) == 59999);
    assert(udp_activity_idle(seen, 61000) == 60000);
    /* A receive-only endpoint remains live when a reverse proxy reply arrives. */
    udp_activity_touch(&seen, 60000);
    assert(udp_activity_idle(seen, 61000) == 1000);
    assert(udp_activity_idle(seen, 119999) == 59999);
    assert(udp_activity_idle(seen, 120000) == 60000);
    udp_activity_touch(NULL, 1);
    assert(udp_activity_idle(seen, 59999) == UINT64_MAX);
    udp_activity_touch(&seen, UINT64_MAX);
    assert(udp_activity_idle(seen, UINT64_MAX) == 0);
}

static void fair_scan(void)
{
    struct udp_reaper scan = {0};
    unsigned int visited[2048] = {0};
    size_t index;
    /* Every turn imitates four expensive notifications. Cursor continuation
       must visit all slots exactly once, rather than restart at slot zero. */
    for (uint64_t turn = 0; turn < 512; ++turn) {
        assert(udp_reaper_begin(&scan, 2048, turn, 300));
        for (int n = 0; n < 4; ++n) {
            assert(udp_reaper_next(&scan, 2048, turn, &index));
            assert(index < 2048);
            ++visited[index];
        }
    }
    assert(!udp_reaper_next(&scan, 2048, 512, &index));
    for (size_t n = 0; n < 2048; ++n) assert(visited[n] == 1);
    assert(!udp_reaper_begin(&scan, 2048, 1511, 300));
    assert(udp_reaper_begin(&scan, 2048, 1512, 300));
    assert(udp_reaper_next(&scan, 2048, 1512, &index) && index == 0);
}

static void deadlines_and_reset(void)
{
    struct udp_reaper scan = {0};
    size_t index = 123;
    assert(udp_reaper_begin(&scan, 8, 1000, 300));
    assert(udp_reaper_next(&scan, 8, 1299, &index) && index == 0);
    assert(!udp_reaper_next(&scan, 8, 1300, &index));
    assert(index == 0 && scan.remaining == 7);
    assert(!udp_reaper_next(&scan, 8, 999, &index));
    assert(udp_reaper_begin(&scan, 8, 2000, 300));
    assert(udp_reaper_next(&scan, 8, 2000, &index) && index == 1);
    /* drop_shim resets the scheduler while a close RPC is in progress. */
    memset(&scan, 0, sizeof(scan));
    assert(!udp_reaper_next(&scan, 8, 2001, &index));
    assert(udp_reaper_begin(&scan, 8, 2001, 300));
    assert(udp_reaper_next(&scan, 8, 2001, &index) && index == 0);
    assert(!udp_reaper_begin(&scan, 8, UINT64_MAX, 1));
    assert(!udp_reaper_begin(&scan, 8, 2001, 0));
    assert(!udp_reaper_begin(NULL, 8, 2001, 1));
    assert(!udp_reaper_begin(&scan, 0, 2001, 1));
    assert(!udp_reaper_next(&scan, 8, 2001, NULL));
    assert(!udp_reaper_next(NULL, 8, 2001, &index));
    assert(!udp_reaper_next(&scan, 0, 2001, &index));
    scan.cursor = 9;
    assert(!udp_reaper_begin(&scan, 8, 2001, 1));
    assert(!udp_reaper_next(&scan, 8, 2001, &index));
    memset(&scan, 0, sizeof(scan));
    assert(udp_reaper_begin(&scan, 1, UINT64_MAX - 1, 1));
    assert(udp_reaper_next(&scan, 1, UINT64_MAX - 1, &index) && index == 0);
    assert(!udp_reaper_next(&scan, 1, UINT64_MAX, &index));
    assert(scan.next_due == UINT64_MAX);
}

int main(void)
{
    activity();
    fair_scan();
    deadlines_and_reset();
    puts("PASS: UDP receive activity, fair bounded maintenance, deadlines, reset and invalid inputs");
    return 0;
}
