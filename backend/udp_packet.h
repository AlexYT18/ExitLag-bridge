#ifndef EXL_UDP_PACKET_H
#define EXL_UDP_PACKET_H

#include <stddef.h>
#include <stdint.h>

#define UDP_PACKET_MAX_PAYLOAD_V4 65507u
#define UDP_PACKET_MAX_PAYLOAD_V6 65527u
#define UDP_PACKET_MAX_SIZE 65575u

enum udp_packet_result {
    UDP_PACKET_OK = 0,
    UDP_PACKET_INVALID = -1,
    UDP_PACKET_UNSUPPORTED = -2,
    UDP_PACKET_CAPACITY = -3
};

struct udp_packet_endpoint {
    int family;
    unsigned char address[16]; /* Network-order bytes; IPv4 uses first four. */
    uint16_t port_net;
};

struct udp_packet_view {
    struct udp_packet_endpoint src;
    struct udp_packet_endpoint dst;
    const unsigned char *payload;
    size_t payload_length;
    uint8_t traffic_class;
    uint8_t hop_limit;
};

/* Only syntactically unscoped unicast endpoints are supported. Loopback is
 * allowed; identifying IPv4 subnet-directed broadcast needs routing context.
 * IPv6
 * IPv4-mapped addresses are not IPv6 wire endpoints: dual-stack IPv4 packets
 * must be supplied as AF_INET. No interface scope is guessed. */
int udp_packet_endpoint_valid(const struct udp_packet_endpoint *endpoint);

/* Decode the project's Windows sockaddr[28]. AF_INET=2, AF_INET6=23 in that
 * record regardless of host constants. Reject metadata/padding/scope that the
 * native backend cannot preserve. Clear output on every failure. */
enum udp_packet_result udp_packet_endpoint_from_wire(
    int family, const unsigned char wire[28], struct udp_packet_endpoint *endpoint);

/* Exact full-packet bounds are required, including UDP wire length. Fragments,
 * IPv4 options, IPv6 extensions and jumbograms are deliberately unsupported.
 * Input checksums are not verified: NFQUEUE can expose checksum-offload packets.
 * A caller must not infer checksum validity from a successful bounds parse.
 * Output is cleared on failure; payload borrows storage from packet. */
enum udp_packet_result udp_packet_parse(
    const void *packet, size_t length, struct udp_packet_view *view);

/* Software validation for complete ingress bytes before active replacement.
 * Checksum-offload placeholders must not be considered valid by the caller.
 * IPv4 header and nonzero UDP checksums are checked; IPv4 UDP checksum zero is
 * permitted by the protocol. IPv6 UDP checksum zero is rejected. Unsupported
 * packets and malformed/truncated input return zero, with no writes. */
int udp_packet_checksums_valid(const void *packet, size_t length);

/* Construct one ordinary IPv4/IPv6 UDP packet with valid IP/UDP checksums.
 * Empty payload is supported with payload=NULL. Both endpoints must have the
 * same family. IPv4 ID/fragment bits and IPv6 flow label are zero; caller's
 * traffic class and nonzero hop limit are retained. Payload may overlap buffer.
 * written must not alias the source packet, endpoint objects or output buffer.
 * On failure no buffer byte changes and *written is zero. */
enum udp_packet_result udp_packet_build(
    void *buffer, size_t capacity,
    const struct udp_packet_endpoint *src, const struct udp_packet_endpoint *dst,
    const void *payload, size_t payload_length,
    uint8_t traffic_class, uint8_t hop_limit, size_t *written);

#endif
