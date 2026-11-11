#include "../backend/udp_peers.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct udp_peers peers = {0}, other = {0};
    unsigned char local[28] = {2}, original[28] = {2,0,10}, posted[28] = {2,0,20};
    int slot = udp_peers_prepare(&peers, local, original, posted, 100, 50);
    assert(slot == 0 && !udp_peer_matches(&peers.entries[slot], local, posted, 100, 50));
    assert(udp_peers_commit(&peers, slot, local, original, posted, 100));
    assert(udp_peer_matches(&peers.entries[slot], local, posted, 149, 50));
    assert(!udp_peer_matches(&peers.entries[slot], local, posted, 150, 50));
    assert(!udp_peer_matches(&peers.entries[slot], local, posted, 99, 50));
    assert(!udp_peer_matches(&other.entries[slot], local, posted, 100, 50));
    assert(udp_peers_prepare(&peers, local, original, posted, 110, 50) == slot);
    unsigned char changed[28]; memcpy(changed, original, 28); ++changed[2];
    assert(!udp_peers_commit(&peers, slot, local, changed, posted, 110));
    for (int i = 1; i < UDP_PEERS_MAX; ++i) {
        original[2] = (unsigned char)(10+i);
        int selected = udp_peers_prepare(&peers, local, original, posted, 110, 50);
        assert(selected == i);
        assert(udp_peers_commit(&peers, selected, local, original, posted, 110));
    }
    original[2] = 100;
    assert(udp_peers_prepare(&peers, local, original, posted, 120, 50) == -1);
    assert(peers.entries[0].original[2] == 10);
    assert(udp_peers_prepare(&peers, local, original, posted, 150, 50) == 0);
    assert(!peers.entries[0].used);
    assert(udp_peers_commit(&peers, 0, local, original, posted, UINT64_MAX-1));
    assert(udp_peer_matches(&peers.entries[0], local, posted, UINT64_MAX, 50));
    assert(!udp_peer_matches(&peers.entries[0], local, posted, 0, 50));
    assert(udp_peers_prepare(&peers, local, original, posted, 0, 50) >= 0);
    assert(!udp_peer_matches(NULL, local, posted, 100, 50));
    assert(!udp_peer_matches(&peers.entries[0], NULL, posted, 100, 50));
    assert(udp_peers_prepare(NULL, local, original, posted, 0, 50) == -1);
    assert(udp_peers_prepare(&peers, local, original, posted, 0, 0) == -1);
    assert(!udp_peers_commit(&peers, -1, local, original, posted, 100));
    assert(!udp_peers_commit(&peers, UDP_PEERS_MAX, local, original, posted, 100));
    puts("PASS: bounded UDP peer prepare/commit, independent endpoints and timeout boundaries");
    return 0;
}
