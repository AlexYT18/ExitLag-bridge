#include "nfq_verdict.h"

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <string.h>
#include <sys/socket.h>

enum {
    verdict_base_length = NLMSG_SPACE(sizeof(struct nfgenmsg)) +
                          NLA_ALIGN(NLA_HDRLEN + sizeof(struct nfqnl_msg_verdict_hdr)),
    verdict_priority_length = NLA_ALIGN(NLA_HDRLEN + sizeof(uint32_t))
};

size_t nfq_verdict_build(void *buffer, size_t capacity, uint16_t queue_num,
                         uint32_t packet_id, uint32_t verdict,
                         const uint32_t *priority)
{
    const size_t needed = verdict_base_length + (priority ? verdict_priority_length : 0);
    if (!buffer || capacity < needed) return 0;

    /* Build aligned locally, then copy: caller buffers need no alignment and
     * a capacity failure never leaves a partially encoded verdict behind. */
    _Alignas(struct nlmsghdr) unsigned char message[verdict_base_length + verdict_priority_length];
    memset(message, 0, sizeof(message));
    struct nlmsghdr *header = mnl_nlmsg_put_header(message);
    header->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
    header->nlmsg_flags = NLM_F_REQUEST;
    struct nfgenmsg *family = mnl_nlmsg_put_extra_header(header, sizeof(*family));
    family->nfgen_family = AF_UNSPEC;
    family->version = NFNETLINK_V0;
    family->res_id = htons(queue_num);
    const struct nfqnl_msg_verdict_hdr decision = { htonl(verdict), htonl(packet_id) };
    mnl_attr_put(header, NFQA_VERDICT_HDR, sizeof(decision), &decision);
    if (priority) mnl_attr_put_u32(header, NFQA_PRIORITY, htonl(*priority));
    memcpy(buffer, message, header->nlmsg_len);
    return header->nlmsg_len;
}

size_t nfq_verdict_build_packet(void *buffer, size_t capacity, uint16_t queue_num,
                                uint32_t packet_id, uint32_t verdict,
                                const uint32_t *priority,
                                const void *packet, size_t packet_length)
{
    if (!packet)
        return packet_length ? 0 : nfq_verdict_build(buffer, capacity, queue_num,
                                                    packet_id, verdict, priority);
    if (packet_length > UINT16_MAX - (size_t)NLA_HDRLEN) return 0;
    const size_t prefix_length = verdict_base_length +
                                 (priority ? verdict_priority_length : 0);
    const size_t attribute_length = NLA_HDRLEN + packet_length;
    const size_t padded_length = NLA_ALIGN(attribute_length);
    const size_t needed = prefix_length + padded_length;
    if (!buffer || capacity < needed) return 0;

    /* Encode the prefix before touching the caller buffer. This also captures
       a priority value aliased into the source packet or destination buffer. */
    _Alignas(struct nlmsghdr) unsigned char prefix[verdict_base_length + verdict_priority_length];
    if (nfq_verdict_build(prefix, sizeof(prefix), queue_num, packet_id, verdict,
                          priority) != prefix_length)
        return 0;
    struct nlmsghdr *header = (struct nlmsghdr *)prefix;
    header->nlmsg_len = (uint32_t)needed;
    unsigned char *output = buffer;
    /* Copy payload first to support in-place full-packet replacement. */
    memmove(output + prefix_length + NLA_HDRLEN, packet, packet_length);
    memcpy(output, prefix, prefix_length);
    const struct nlattr attribute = {
        .nla_len = (uint16_t)attribute_length,
        .nla_type = NFQA_PAYLOAD
    };
    _Static_assert(sizeof(attribute) == NLA_HDRLEN, "Unexpected netlink attribute padding");
    memcpy(output + prefix_length, &attribute, sizeof(attribute));
    memset(output + prefix_length + attribute_length, 0,
           padded_length - attribute_length);
    return needed;
}

int nfq_priority_read(const struct nlattr *attribute, uint32_t *priority)
{
    if (!priority) return 0;
    *priority = 0;
    if (!attribute) return 1;
    if (attribute->nla_len != NLA_HDRLEN + sizeof(uint32_t) ||
        mnl_attr_get_type(attribute) != NFQA_PRIORITY)
        return 0;
    uint32_t network_priority;
    memcpy(&network_priority, mnl_attr_get_payload(attribute), sizeof(network_priority));
    *priority = ntohl(network_priority);
    return 1;
}
