#include "../backend/nfq_verdict.h"

#include <arpa/inet.h>
#include <assert.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

struct decoded {
    const struct nlattr *verdict;
    const struct nlattr *priority;
    const struct nlattr *packet;
    unsigned int attributes;
};

static int collect(const struct nlattr *attribute, void *argument)
{
    struct decoded *decoded = argument;
    switch (mnl_attr_get_type(attribute)) {
    case NFQA_VERDICT_HDR:
        assert(!decoded->verdict);
        decoded->verdict = attribute;
        break;
    case NFQA_PRIORITY:
        assert(!decoded->priority);
        decoded->priority = attribute;
        break;
    case NFQA_PAYLOAD:
        assert(!decoded->packet);
        decoded->packet = attribute;
        break;
    default:
        /* In particular, no NFQA_MARK may unexpectedly alter policy routing. */
        assert(!"unexpected verdict attribute");
    }
    ++decoded->attributes;
    return MNL_CB_OK;
}

static void check_message(uint16_t queue, uint32_t id, uint32_t verdict,
                           const uint32_t *priority)
{
    _Alignas(struct nlmsghdr) unsigned char storage[128];
    memset(storage, 0xa5, sizeof(storage));
    const size_t length = nfq_verdict_build(storage, sizeof(storage), queue, id, verdict, priority);
    assert(length && length <= sizeof(storage));
    const struct nlmsghdr *header = (const struct nlmsghdr *)storage;
    assert(header->nlmsg_len == length);
    assert(header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT));
    assert(header->nlmsg_flags == NLM_F_REQUEST);
    assert(header->nlmsg_seq == 0 && header->nlmsg_pid == 0);
    const struct nfgenmsg *family = mnl_nlmsg_get_payload(header);
    assert(family->nfgen_family == AF_UNSPEC && family->version == NFNETLINK_V0);
    assert(ntohs(family->res_id) == queue);
    const unsigned char *queue_wire = (const unsigned char *)&family->res_id;
    assert(queue_wire[0] == (queue >> 8) && queue_wire[1] == (queue & 255));

    struct decoded decoded = {0};
    assert(mnl_attr_parse(header, sizeof(*family), collect, &decoded) == MNL_CB_OK);
    assert(decoded.verdict);
    assert(mnl_attr_get_payload_len(decoded.verdict) == sizeof(struct nfqnl_msg_verdict_hdr));
    const struct nfqnl_msg_verdict_hdr *decision = mnl_attr_get_payload(decoded.verdict);
    assert(ntohl(decision->id) == id && ntohl(decision->verdict) == verdict);
    assert(decoded.attributes == (priority ? 2u : 1u));
    assert(!!decoded.priority == !!priority);
    uint32_t read_priority = 0xdeadbeef;
    assert(nfq_priority_read(decoded.priority, &read_priority));
    assert(read_priority == (priority ? *priority : 0));
    if (priority) {
        const unsigned char *wire = mnl_attr_get_payload(decoded.priority);
        assert(mnl_attr_get_payload_len(decoded.priority) == 4);
        for (unsigned int i = 0; i < 4; ++i)
            assert(wire[i] == ((*priority >> (24 - i * 8)) & 255));
    }
    for (size_t i = length; i < sizeof(storage); ++i) assert(storage[i] == 0xa5);

    /* Exact-fit and deliberately unaligned caller buffers are supported. */
    unsigned char copy[129];
    memset(copy, 0x5a, sizeof(copy));
    assert(nfq_verdict_build(copy + 1, length, queue, id, verdict, priority) == length);
    assert(copy[0] == 0x5a && copy[length + 1] == 0x5a);
    assert(!memcmp(copy + 1, storage, length));
    for (size_t capacity = 0; capacity < length; ++capacity) {
        memset(copy, 0x5a, sizeof(copy));
        assert(nfq_verdict_build(copy + 1, capacity, queue, id, verdict, priority) == 0);
        for (size_t i = 0; i < sizeof(copy); ++i) assert(copy[i] == 0x5a);
    }
    assert(nfq_verdict_build(NULL, sizeof(copy), queue, id, verdict, priority) == 0);
}

static void priority_validation(void)
{
    _Alignas(struct nlattr) unsigned char storage[32];
    memset(storage, 0, sizeof(storage));
    struct nlattr *attribute = (struct nlattr *)storage;
    attribute->nla_type = NFQA_PRIORITY;
    uint32_t priority = 123;
    assert(nfq_priority_read(NULL, &priority) && priority == 0);
    assert(!nfq_priority_read(attribute, NULL));
    const unsigned short invalid_lengths[] = {0, 1, NLA_HDRLEN - 1, NLA_HDRLEN,
        NLA_HDRLEN + 1, NLA_HDRLEN + 2, NLA_HDRLEN + 3, NLA_HDRLEN + 5,
        NLA_HDRLEN + 8};
    for (size_t i = 0; i < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]); ++i) {
        priority = EXL_TCP_AUTH_PRIORITY;
        attribute->nla_len = invalid_lengths[i];
        assert(!nfq_priority_read(attribute, &priority));
        assert(priority == 0);
    }
    attribute->nla_len = NLA_HDRLEN + sizeof(uint32_t);
    attribute->nla_type = NFQA_MARK;
    priority = EXL_TCP_AUTH_PRIORITY;
    assert(!nfq_priority_read(attribute, &priority) && priority == 0);
}

static void packet_replacement(size_t packet_length, const uint32_t *priority)
{
    static unsigned char packet[UINT16_MAX - NLA_HDRLEN];
    _Alignas(struct nlmsghdr) static unsigned char storage[70000];
    static unsigned char unaligned[70001];
    for (size_t i = 0; i < sizeof(packet); ++i) packet[i] = (unsigned char)(i * 17u + 7u);
    memset(storage, 0xa5, sizeof(storage));
    const size_t length = nfq_verdict_build_packet(storage, sizeof(storage),
        0xabcd, 0x87654321, NF_ACCEPT, priority, packet, packet_length);
    assert(length > packet_length && length < sizeof(storage));
    struct nlmsghdr *header = (struct nlmsghdr *)storage;
    assert(header->nlmsg_len == length);
    assert(header->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT));
    assert(header->nlmsg_flags == NLM_F_REQUEST);
    const struct nfgenmsg *family = mnl_nlmsg_get_payload(header);
    assert(family->nfgen_family == AF_UNSPEC && family->version == NFNETLINK_V0);
    assert(ntohs(family->res_id) == 0xabcd);
    struct decoded decoded = {0};
    assert(mnl_attr_parse(header, sizeof(*family), collect, &decoded) == MNL_CB_OK);
    assert(decoded.verdict && decoded.packet);
    const struct nfqnl_msg_verdict_hdr *decision = mnl_attr_get_payload(decoded.verdict);
    assert(ntohl(decision->id) == 0x87654321 && ntohl(decision->verdict) == NF_ACCEPT);
    assert(decoded.attributes == (priority ? 3u : 2u));
    assert(!!decoded.priority == !!priority);
    if (priority) assert(ntohl(mnl_attr_get_u32(decoded.priority)) == *priority);
    assert(mnl_attr_get_payload_len(decoded.packet) == packet_length);
    assert(decoded.packet->nla_len == NLA_HDRLEN + packet_length);
    assert(!memcmp(mnl_attr_get_payload(decoded.packet), packet, packet_length));
    const size_t attribute_end = (const unsigned char *)decoded.packet - storage + decoded.packet->nla_len;
    for (size_t i = attribute_end; i < length; ++i) assert(storage[i] == 0);
    for (size_t i = length; i < sizeof(storage); ++i) assert(storage[i] == 0xa5);

    /* Exact-fit output may be unaligned, without changing surrounding bytes. */
    memset(unaligned, 0x5a, sizeof(unaligned));
    assert(nfq_verdict_build_packet(unaligned + 1, length, 0xabcd, 0x87654321,
                                    NF_ACCEPT, priority, packet, packet_length) == length);
    assert(!memcmp(unaligned + 1, storage, length));
    assert(unaligned[0] == 0x5a && unaligned[length + 1] == 0x5a);
    const size_t capacities[] = {0, 1, 16, length / 2, length - 1};
    for (size_t n = 0; n < sizeof(capacities) / sizeof(capacities[0]); ++n) {
        memset(unaligned, 0x5a, sizeof(unaligned));
        assert(nfq_verdict_build_packet(unaligned + 1, capacities[n], 0xabcd, 0x87654321,
                                        NF_ACCEPT, priority, packet, packet_length) == 0);
        for (size_t i = 0; i < sizeof(unaligned); ++i) assert(unaligned[i] == 0x5a);
    }

    /* A packet can begin before or after its final attribute location. */
    const size_t offsets[] = {0, 1, 50};
    for (size_t n = 0; n < sizeof(offsets) / sizeof(offsets[0]); ++n) {
        const size_t offset = offsets[n];
        memcpy(storage + offset, packet, packet_length);
        assert(nfq_verdict_build_packet(storage, sizeof(storage), 0xabcd, 0x87654321,
                                        NF_ACCEPT, priority, storage + offset, packet_length) == length);
        decoded = (struct decoded){0};
        assert(mnl_attr_parse((struct nlmsghdr *)storage, sizeof(*family), collect, &decoded) == MNL_CB_OK);
        assert(decoded.packet && mnl_attr_get_payload_len(decoded.packet) == packet_length);
        assert(!memcmp(mnl_attr_get_payload(decoded.packet), packet, packet_length));
    }
}

static void packet_rejections_and_absence(void)
{
    _Alignas(struct nlmsghdr) unsigned char storage[128], original[128];
    const uint32_t priority = 0x12345678;
    const size_t size = nfq_verdict_build(original, sizeof(original), 1, 2, NF_ACCEPT, &priority);
    assert(nfq_verdict_build_packet(storage, sizeof(storage), 1, 2, NF_ACCEPT,
                                    &priority, NULL, 0) == size);
    assert(!memcmp(original, storage, size));
    const size_t bad_lengths[] = {UINT16_MAX - NLA_HDRLEN + 1u, UINT16_MAX, SIZE_MAX};
    for (size_t n = 0; n < sizeof(bad_lengths) / sizeof(bad_lengths[0]); ++n) {
        memset(storage, 0x5a, sizeof(storage));
        assert(!nfq_verdict_build_packet(storage, sizeof(storage), 0, 0, NF_ACCEPT,
                                          NULL, "x", bad_lengths[n]));
        for (size_t i = 0; i < sizeof(storage); ++i) assert(storage[i] == 0x5a);
    }
    memset(storage, 0x5a, sizeof(storage));
    assert(!nfq_verdict_build_packet(storage, sizeof(storage), 0, 0, NF_ACCEPT, NULL, NULL, 1));
    assert(!nfq_verdict_build_packet(NULL, sizeof(storage), 0, 0, NF_ACCEPT, NULL, "x", 1));
    for (size_t i = 0; i < sizeof(storage); ++i) assert(storage[i] == 0x5a);
}

int main(void)
{
    check_message(0, 0, NF_ACCEPT, NULL);
    check_message(UINT16_MAX, UINT32_MAX, NF_DROP, NULL);
    const uint32_t priorities[] = {0, 1, 6, 0x12345678, EXL_TCP_AUTH_PRIORITY,
                                    EXL_TCP_AUTH_PRIORITY | 6, UINT32_MAX};
    for (size_t i = 0; i < sizeof(priorities) / sizeof(priorities[0]); ++i)
        check_message(0x1234, 0x56789abc, NF_ACCEPT, &priorities[i]);
    priority_validation();
    const size_t packet_lengths[] = {0, 1, 3, 28, UINT16_MAX - NLA_HDRLEN};
    const uint32_t priority = EXL_TCP_AUTH_PRIORITY | 6;
    for (size_t i = 0; i < sizeof(packet_lengths) / sizeof(packet_lengths[0]); ++i) {
        packet_replacement(packet_lengths[i], NULL);
        packet_replacement(packet_lengths[i], &priority);
    }
    packet_rejections_and_absence();
    puts("PASS: NFQUEUE verdict wire encoding, packet replacement, bounds, priority and fwmark isolation");
    return 0;
}
