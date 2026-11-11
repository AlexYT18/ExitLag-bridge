#ifndef EXL_UDP_ATTRIBUTION_H
#define EXL_UDP_ATTRIBUTION_H

enum udp_attribution_result {
    UDP_ATTR_INVALID = -2,
    UDP_ATTR_AMBIGUOUS = -1,
    UDP_ATTR_NONE = 0,
    UDP_ATTR_FOUND = 1
};

/* Address bytes are network-order; ports are host-order. A connected socket
 * must match both endpoints; an unconnected socket may match ANY bind/peer.
 * Distinct compatible inodes are ambiguous, including exact/wildcard overlap.
 * Both tables are checked for IPv4, with BOTH endpoints mapped for udp6.
 * An IPv6 ANY bind cannot prove IPV6_V6ONLY for IPv4, so is ambiguous.
 * Missing/malformed/oversized tables and IPv6 link-local scope are INVALID.
 * Every result other than FOUND clears *inode_out. This does not lock a socket
 * against a later close/rebind; callers must verify its process and held fd. */
enum udp_attribution_result udp_attribution_lookup_files(
    const char *udp_path, const char *udp6_path, int family,
    const unsigned char *local_ip, unsigned short local_port,
    const unsigned char *remote_ip, unsigned short remote_port,
    unsigned long *inode_out);

enum udp_attribution_result udp_attribution_lookup(
    int family, const unsigned char *local_ip, unsigned short local_port,
    const unsigned char *remote_ip, unsigned short remote_port,
    unsigned long *inode_out);

#endif
