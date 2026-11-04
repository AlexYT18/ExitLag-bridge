#ifndef EXITLAG_NFQ_VERDICT_H
#define EXITLAG_NFQ_VERDICT_H

#include <stddef.h>
#include <stdint.h>

struct nlattr;

/* Reserved only while a TCP SYN travels between our queue and NAT hooks. */
#define EXL_TCP_AUTH_PRIORITY UINT32_C(0x80000000)

/* Returns the encoded length, or zero without changing buffer on failure.
 * A NULL priority leaves skb->priority unchanged; otherwise it is explicit,
 * including when its value is zero. No packet fwmark is written. */
size_t nfq_verdict_build(void *buffer, size_t capacity, uint16_t queue_num,
                         uint32_t packet_id, uint32_t verdict,
                         const uint32_t *priority);

/* Optional full-packet replacement through NFQA_PAYLOAD. A NULL packet with
 * packet_length zero emits the same bytes as nfq_verdict_build; a non-NULL
 * packet emits the attribute even for an explicit empty replacement. The
 * packet must fit the 16-bit netlink attribute length (at most 65531 bytes).
 * Source packet and output buffer may overlap. All validation precedes writes;
 * on failure returns zero and leaves every output byte unchanged. No fwmark
 * attribute is written. */
size_t nfq_verdict_build_packet(void *buffer, size_t capacity, uint16_t queue_num,
                                uint32_t packet_id, uint32_t verdict,
                                const uint32_t *priority,
                                const void *packet, size_t packet_length);

/* The caller must supply a bounded attribute from a validated netlink frame.
 * An absent attribute means priority zero. Malformed attributes fail closed
 * and clear the output, so an earlier authorization cannot be reused. */
int nfq_priority_read(const struct nlattr *attribute, uint32_t *priority);

#endif
