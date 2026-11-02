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

int main(void)
{
    check_message(0, 0, NF_ACCEPT, NULL);
    check_message(UINT16_MAX, UINT32_MAX, NF_DROP, NULL);
    const uint32_t priorities[] = {0, 1, 6, 0x12345678, EXL_TCP_AUTH_PRIORITY,
                                    EXL_TCP_AUTH_PRIORITY | 6, UINT32_MAX};
    for (size_t i = 0; i < sizeof(priorities) / sizeof(priorities[0]); ++i)
        check_message(0x1234, 0x56789abc, NF_ACCEPT, &priorities[i]);
    priority_validation();
    puts("PASS: NFQUEUE verdict wire encoding, bounds, priority and fwmark isolation");
    return 0;
}
