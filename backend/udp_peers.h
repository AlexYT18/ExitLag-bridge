#ifndef EXL_UDP_PEERS_H
#define EXL_UDP_PEERS_H
#include <stdint.h>

#define UDP_PEERS_MAX 16
struct udp_peer {
    int used;
    unsigned char local[28], original[28], posted[28];
    uint64_t last_ms;
};
struct udp_peers { struct udp_peer entries[UDP_PEERS_MAX]; };

/* Addresses are canonical wire sockaddrs validated by the caller. A slot is
 * activated only after successful delivery. Active entries are never evicted. */
int udp_peers_prepare(struct udp_peers *peers, const unsigned char local[28],
                     const unsigned char original[28], const unsigned char posted[28],
                     uint64_t now_ms, uint64_t ttl_ms);
int udp_peers_commit(struct udp_peers *peers, int slot, const unsigned char local[28],
                    const unsigned char original[28], const unsigned char posted[28],
                    uint64_t now_ms);
int udp_peer_matches(const struct udp_peer *peer, const unsigned char local[28],
                     const unsigned char posted[28], uint64_t now_ms, uint64_t ttl_ms);
#endif
