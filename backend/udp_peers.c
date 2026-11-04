#include "udp_peers.h"
#include <string.h>

static int alive(const struct udp_peer *peer, uint64_t now, uint64_t ttl)
{
    return peer && peer->used && ttl && now >= peer->last_ms && now - peer->last_ms < ttl;
}

static int key(const struct udp_peer *peer, const unsigned char *local,
               const unsigned char *original, const unsigned char *posted)
{
    return !memcmp(peer->local, local, 28) && !memcmp(peer->original, original, 28) &&
           !memcmp(peer->posted, posted, 28);
}

int udp_peers_prepare(struct udp_peers *peers, const unsigned char local[28],
                     const unsigned char original[28], const unsigned char posted[28],
                     uint64_t now, uint64_t ttl)
{
    if (!peers || !local || !original || !posted || !ttl) return -1;
    int vacant = -1;
    for (int i = 0; i < UDP_PEERS_MAX; ++i) {
        struct udp_peer *peer = &peers->entries[i];
        if (!alive(peer, now, ttl)) memset(peer, 0, sizeof(*peer));
        if (peer->used && key(peer, local, original, posted)) return i;
        if (!peer->used && vacant < 0) vacant = i;
    }
    return vacant;
}

int udp_peers_commit(struct udp_peers *peers, int slot, const unsigned char local[28],
                    const unsigned char original[28], const unsigned char posted[28],
                    uint64_t now)
{
    if (!peers || slot < 0 || slot >= UDP_PEERS_MAX || !local || !original || !posted)
        return 0;
    struct udp_peer *peer = &peers->entries[slot];
    if (peer->used && !key(peer, local, original, posted)) return 0;
    memcpy(peer->local, local, 28); memcpy(peer->original, original, 28);
    memcpy(peer->posted, posted, 28); peer->last_ms = now; peer->used = 1;
    return 1;
}

int udp_peer_matches(const struct udp_peer *peer, const unsigned char local[28],
                     const unsigned char posted[28], uint64_t now, uint64_t ttl)
{
    return local && posted && alive(peer, now, ttl) &&
           !memcmp(peer->local, local, 28) && !memcmp(peer->posted, posted, 28);
}
