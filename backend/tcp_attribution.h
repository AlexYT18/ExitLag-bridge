#ifndef EXL_TCP_ATTRIBUTION_H
#define EXL_TCP_ATTRIBUTION_H

enum tcp_attribution_result {
    TCP_ATTR_INVALID = -2,
    TCP_ATTR_AMBIGUOUS = -1,
    TCP_ATTR_NONE = 0,
    TCP_ATTR_FOUND = 1
};

/* Addresses are network-order bytes; ports are host-order. On every result
 * except FOUND, *inode_out is zero. Missing/unreadable/malformed tables fail
 * closed with INVALID. IPv4 also checks tcp6 with BOTH endpoints mapped.
 * IPv6 link-local tuples are INVALID: /proc omits their required scope IDs. */
enum tcp_attribution_result tcp_attribution_lookup_files(
    const char *tcp_path, const char *tcp6_path, int family,
    const unsigned char *local_ip, unsigned short local_port,
    const unsigned char *remote_ip, unsigned short remote_port,
    unsigned long *inode_out);

enum tcp_attribution_result tcp_attribution_lookup(
    int family, const unsigned char *local_ip, unsigned short local_port,
    const unsigned char *remote_ip, unsigned short remote_port,
    unsigned long *inode_out);

#endif
