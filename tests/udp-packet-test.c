#include "../backend/udp_packet.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static unsigned int checks;
#define CHECK(condition) do { ++checks; assert(condition); } while (0)

static struct udp_packet_endpoint endpoint(int family, const char *address, unsigned short port)
{
    struct udp_packet_endpoint result = {0};
    result.family = family;
    result.port_net = htons(port);
    CHECK(inet_pton(family, address, result.address) == 1);
    return result;
}

/* Independent reference: byte-position contributions, 64-bit accumulator and
 * modulo-65535 arithmetic, rather than the codec's word-add/fold functions. */
static uint16_t reference_checksum(const unsigned char *bytes, size_t length)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < length; ++i)
        sum += (uint64_t)bytes[i] << (i % 2 ? 0 : 8);
    uint64_t residue = sum % 65535u;
    if (!residue && sum) residue = 65535u;
    return (uint16_t)(65535u - residue);
}

static void validate_checksums(const unsigned char *packet, size_t size, int family)
{
    unsigned char pseudo[40];
    unsigned char combined[40 + 65535];
    const size_t ip_size = family == AF_INET ? 20 : 40;
    const size_t udp_size = size - ip_size;
    size_t pseudo_size;
    memset(pseudo, 0, sizeof(pseudo));
    if (family == AF_INET) {
        CHECK(reference_checksum(packet, ip_size) == 0);
        memcpy(pseudo, packet + 12, 8);
        pseudo[9] = 17;
        pseudo[10] = (unsigned char)(udp_size >> 8);
        pseudo[11] = (unsigned char)udp_size;
        pseudo_size = 12;
    } else {
        memcpy(pseudo, packet + 8, 32);
        pseudo[34] = (unsigned char)(udp_size >> 8);
        pseudo[35] = (unsigned char)udp_size;
        pseudo[39] = 17;
        pseudo_size = 40;
    }
    memcpy(combined, pseudo, pseudo_size);
    memcpy(combined + pseudo_size, packet + ip_size, udp_size);
    CHECK(reference_checksum(combined, pseudo_size + udp_size) == 0);
    CHECK(packet[ip_size + 6] || packet[ip_size + 7]);
}

static size_t hex_bytes(const char *hex, unsigned char *out)
{
    size_t length = strlen(hex);
    CHECK(!(length % 2));
    for (size_t i = 0; i < length / 2; ++i) {
        unsigned int value;
        CHECK(sscanf(hex + i * 2, "%2x", &value) == 1);
        out[i] = (unsigned char)value;
    }
    return length / 2;
}

static void known_vectors(void)
{
    const unsigned char rfc1071[] = {0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7};
    CHECK(reference_checksum(rfc1071, sizeof(rfc1071)) == 0x220d);
    static const char *vectors[] = {
        "452e001f0000000040118e69c0000201c6336402303901bb000b1d4a616263",
        "62e00000000b113f20010db800000000000000000000000120010db8000000000000000000000002303901bb000bae0c616263"
    };
    for (int v6 = 0; v6 < 2; ++v6) {
        const int family = v6 ? AF_INET6 : AF_INET;
        struct udp_packet_endpoint source = endpoint(family, v6 ? "2001:db8::1" : "192.0.2.1", 12345);
        struct udp_packet_endpoint destination = endpoint(family, v6 ? "2001:db8::2" : "198.51.100.2", 443);
        unsigned char expected[128], output[128];
        const size_t expected_size = hex_bytes(vectors[v6], expected);
        size_t written = 999;
        CHECK(udp_packet_build(output, sizeof(output), &source, &destination, "abc", 3,
                               0x2e, v6 ? 63 : 64, &written) == UDP_PACKET_OK);
        CHECK(written == expected_size && !memcmp(output, expected, written));
        validate_checksums(output, written, family);
        CHECK(udp_packet_checksums_valid(expected, expected_size));
        struct udp_packet_view view;
        CHECK(udp_packet_parse(expected, expected_size, &view) == UDP_PACKET_OK);
        CHECK(view.payload_length == 3 && !memcmp(view.payload, "abc", 3));
        CHECK(view.src.family == family && view.dst.family == family);
        CHECK(view.src.port_net == source.port_net && view.dst.port_net == destination.port_net);
        CHECK(!memcmp(view.src.address, source.address, 16));
        CHECK(!memcmp(view.dst.address, destination.address, 16));
        CHECK(view.traffic_class == 0x2e && view.hop_limit == (v6 ? 63 : 64));
    }
}

static void payload_boundaries(void)
{
    static unsigned char payload[UDP_PACKET_MAX_PAYLOAD_V6 + 1];
    static unsigned char storage[UDP_PACKET_MAX_SIZE + 2];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (unsigned char)(i * 101u + 31u);
    for (int v6 = 0; v6 < 2; ++v6) {
        const int family = v6 ? AF_INET6 : AF_INET;
        const size_t maximum = v6 ? UDP_PACKET_MAX_PAYLOAD_V6 : UDP_PACKET_MAX_PAYLOAD_V4;
        const size_t header = v6 ? 48 : 28;
        const size_t lengths[] = {0, 1, 2, 3, 7, 64, 511, 1500, maximum - 1, maximum};
        struct udp_packet_endpoint source = endpoint(family, v6 ? "2001:db8:1::a" : "192.0.2.10", 51000);
        struct udp_packet_endpoint destination = endpoint(family, v6 ? "2001:db8:1::b" : "198.51.100.11", 60000);
        for (size_t n = 0; n < sizeof(lengths) / sizeof(lengths[0]); ++n) {
            const size_t length = lengths[n];
            memset(storage, 0xa5, sizeof(storage));
            size_t written = 999;
            CHECK(udp_packet_build(storage + 1, header + length, &source, &destination,
                                   length ? payload : NULL, length, 0xfd, 1, &written) == UDP_PACKET_OK);
            CHECK(written == header + length);
            CHECK(storage[0] == 0xa5 && storage[written + 1] == 0xa5);
            CHECK(!memcmp(storage + 1 + header, payload, length));
            validate_checksums(storage + 1, written, family);
            CHECK(udp_packet_checksums_valid(storage + 1, written));
            struct udp_packet_view view;
            CHECK(udp_packet_parse(storage + 1, written, &view) == UDP_PACKET_OK);
            CHECK(view.payload_length == length && view.traffic_class == 0xfd && view.hop_limit == 1);
            CHECK(!memcmp(view.payload, payload, length));

            memset(storage, 0xa5, sizeof(storage));
            CHECK(udp_packet_build(storage + 1, header + length - 1, &source, &destination,
                                   payload, length, 0, 64, &written) == UDP_PACKET_CAPACITY);
            CHECK(written == 0);
            for (size_t i = 0; i < sizeof(storage); ++i) CHECK(storage[i] == 0xa5);
        }
        size_t written = 999;
        CHECK(udp_packet_build(storage, sizeof(storage), &source, &destination,
                               payload, maximum + 1, 0, 64, &written) == UDP_PACKET_INVALID);
        CHECK(written == 0);
        CHECK(udp_packet_build(storage, sizeof(storage), &source, &destination,
                               payload, SIZE_MAX, 0, 64, &written) == UDP_PACKET_INVALID);
        CHECK(written == 0);

        /* Force the calculated checksum to zero; wire checksum must be ffff. */
        unsigned char adjustment[2] = {0};
        CHECK(udp_packet_build(storage, sizeof(storage), &source, &destination,
                               adjustment, 2, 0, 64, &written) == UDP_PACKET_OK);
        adjustment[0] = storage[header - 2]; adjustment[1] = storage[header - 1];
        CHECK(udp_packet_build(storage, sizeof(storage), &source, &destination,
                               adjustment, 2, 0, 64, &written) == UDP_PACKET_OK);
        CHECK(storage[header - 2] == 255 && storage[header - 1] == 255);
        validate_checksums(storage, written, family);

        unsigned char original[31];
        memcpy(original, payload, sizeof(original));
        memcpy(storage + 3, original, sizeof(original));
        CHECK(udp_packet_build(storage, sizeof(storage), &source, &destination,
                               storage + 3, sizeof(original), 0, 64, &written) == UDP_PACKET_OK);
        CHECK(!memcmp(storage + header, original, sizeof(original)));
        validate_checksums(storage, written, family);
    }
}

static void endpoints_and_wire(void)
{
    static const char *bad4[] = {"0.0.0.0", "0.2.3.4", "224.0.0.1", "239.1.2.3", "240.1.2.3", "255.255.255.255"};
    static const char *bad6[] = {"::", "fe80::1", "febf::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:192.0.2.1"};
    for (size_t i = 0; i < sizeof(bad4) / sizeof(bad4[0]); ++i) {
        struct udp_packet_endpoint invalid = endpoint(AF_INET, bad4[i], 1000);
        CHECK(!udp_packet_endpoint_valid(&invalid));
    }
    for (size_t i = 0; i < sizeof(bad6) / sizeof(bad6[0]); ++i) {
        struct udp_packet_endpoint invalid = endpoint(AF_INET6, bad6[i], 1000);
        CHECK(!udp_packet_endpoint_valid(&invalid));
    }
    CHECK(!udp_packet_endpoint_valid(NULL));
    for (int v6 = 0; v6 < 2; ++v6) {
        const int family = v6 ? AF_INET6 : AF_INET;
        struct udp_packet_endpoint expected = endpoint(family, v6 ? "::1" : "127.0.0.2", 65535);
        CHECK(udp_packet_endpoint_valid(&expected));
        unsigned char wire[28] = {0};
        wire[0] = v6 ? 23 : 2;
        memcpy(wire + 2, &expected.port_net, 2);
        memcpy(wire + (v6 ? 8 : 4), expected.address, v6 ? 16 : 4);
        struct udp_packet_endpoint actual;
        CHECK(udp_packet_endpoint_from_wire(family, wire, &actual) == UDP_PACKET_OK);
        CHECK(actual.family == family && actual.port_net == expected.port_net);
        CHECK(!memcmp(actual.address, expected.address, 16));
        for (size_t offset = v6 ? 4 : 8; offset < 28; ++offset) {
            if (v6 && offset >= 8 && offset < 24) continue;
            wire[offset] = 1;
            memset(&actual, 0xa5, sizeof(actual));
            CHECK(udp_packet_endpoint_from_wire(family, wire, &actual) == UDP_PACKET_UNSUPPORTED);
            struct udp_packet_endpoint zero = {0};
            CHECK(!memcmp(&actual, &zero, sizeof(actual)));
            wire[offset] = 0;
        }
        wire[0] = v6 ? AF_INET6 : 23;
        CHECK(udp_packet_endpoint_from_wire(family, wire, &actual) == UDP_PACKET_INVALID);
        wire[0] = v6 ? 23 : 2;
        wire[2] = wire[3] = 0;
        CHECK(udp_packet_endpoint_from_wire(family, wire, &actual) == UDP_PACKET_UNSUPPORTED);
        CHECK(udp_packet_endpoint_from_wire(family, NULL, &actual) == UDP_PACKET_INVALID);
        CHECK(udp_packet_endpoint_from_wire(family, wire, NULL) == UDP_PACKET_INVALID);
        expected.port_net = 0;
        CHECK(!udp_packet_endpoint_valid(&expected));
    }
}

static void parse_failure(const void *packet, size_t size, enum udp_packet_result expected)
{
    struct udp_packet_view view, zero;
    memset(&view, 0xa5, sizeof(view)); memset(&zero, 0, sizeof(zero));
    CHECK(udp_packet_parse(packet, size, &view) == expected);
    CHECK(!memcmp(&view, &zero, sizeof(view)));
}

static void malformed_packets(void)
{
    unsigned char original[128], packet[128];
    for (int v6 = 0; v6 < 2; ++v6) {
        const int family = v6 ? AF_INET6 : AF_INET;
        const size_t ip_size = v6 ? 40 : 20;
        struct udp_packet_endpoint source = endpoint(family, v6 ? "2001:db8::1" : "192.0.2.1", 50000);
        struct udp_packet_endpoint destination = endpoint(family, v6 ? "2001:db8::2" : "198.51.100.2", 50001);
        size_t size;
        CHECK(udp_packet_build(original, sizeof(original), &source, &destination,
                               "abc", 3, 0, 64, &size) == UDP_PACKET_OK);
        for (size_t length = 0; length < size; ++length)
            parse_failure(original, length, UDP_PACKET_INVALID);
        parse_failure(original, size + 1, UDP_PACKET_INVALID);
        memcpy(packet, original, size); packet[0] = 0x10;
        parse_failure(packet, size, UDP_PACKET_INVALID);
        memcpy(packet, original, size); packet[ip_size + 4] = packet[ip_size + 5] = 0;
        parse_failure(packet, size, UDP_PACKET_INVALID);
        memcpy(packet, original, size); packet[ip_size + 5] = 7;
        parse_failure(packet, size, UDP_PACKET_INVALID);
        memcpy(packet, original, size); packet[ip_size + 5]++;
        parse_failure(packet, size, UDP_PACKET_INVALID);
        memcpy(packet, original, size); packet[ip_size] = packet[ip_size + 1] = 0;
        parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
        memcpy(packet, original, size); packet[v6 ? 7 : 8] = 0;
        parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
        memcpy(packet, original, size); memset(packet + (v6 ? 8 : 12), 0, v6 ? 16 : 4);
        parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
        if (v6) {
            const unsigned char next_headers[] = {0, 6, 43, 44, 50, 51, 59, 60};
            for (size_t i = 0; i < sizeof(next_headers); ++i) {
                memcpy(packet, original, size); packet[6] = next_headers[i];
                parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
            }
            memcpy(packet, original, size); packet[4] = packet[5] = 0;
            parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
        } else {
            memcpy(packet, original, size); packet[0] = 0x44;
            parse_failure(packet, size, UDP_PACKET_INVALID);
            memcpy(packet, original, size); packet[0] = 0x46;
            parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
            memcpy(packet, original, size); packet[6] = 0x20;
            parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
            memcpy(packet, original, size); packet[7] = 1;
            parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
            memcpy(packet, original, size); packet[6] = 0x80;
            parse_failure(packet, size, UDP_PACKET_INVALID);
            memcpy(packet, original, size); packet[9] = 6;
            parse_failure(packet, size, UDP_PACKET_UNSUPPORTED);
            /* DF is valid; incoming checksums may be unfinished by offload. */
            memcpy(packet, original, size); packet[6] = 0x40; packet[10] = packet[11] = 0;
            struct udp_packet_view view;
            CHECK(udp_packet_parse(packet, size, &view) == UDP_PACKET_OK);
        }
        /* Do not reject an otherwise bounded offload packet solely for csum0. */
        memcpy(packet, original, size); packet[ip_size + 6] = packet[ip_size + 7] = 0;
        struct udp_packet_view view;
        CHECK(udp_packet_parse(packet, size, &view) == UDP_PACKET_OK);
    }
    parse_failure(NULL, 0, UDP_PACKET_INVALID);
    CHECK(udp_packet_parse(packet, sizeof(packet), NULL) == UDP_PACKET_INVALID);
}

static void build_rejections(void)
{
    unsigned char output[128]; memset(output, 0xa5, sizeof(output));
    struct udp_packet_endpoint source = endpoint(AF_INET, "192.0.2.1", 1);
    struct udp_packet_endpoint destination = endpoint(AF_INET, "198.51.100.2", 2);
    struct udp_packet_endpoint other = endpoint(AF_INET6, "2001:db8::1", 2);
    size_t written = 999;
    CHECK(udp_packet_build(output, sizeof(output), &source, &other, "x", 1, 0, 64, &written) == UDP_PACKET_INVALID);
    CHECK(!written);
    CHECK(udp_packet_build(output, sizeof(output), NULL, &destination, "x", 1, 0, 64, &written) == UDP_PACKET_INVALID);
    CHECK(udp_packet_build(output, sizeof(output), &source, &destination, NULL, 1, 0, 64, &written) == UDP_PACKET_INVALID);
    CHECK(udp_packet_build(NULL, sizeof(output), &source, &destination, NULL, 0, 0, 64, &written) == UDP_PACKET_INVALID);
    CHECK(udp_packet_build(output, sizeof(output), &source, &destination, NULL, 0, 0, 64, NULL) == UDP_PACKET_INVALID);
    CHECK(udp_packet_build(output, sizeof(output), &source, &destination, NULL, 0, 0, 0, &written) == UDP_PACKET_UNSUPPORTED);
    source.port_net = 0;
    CHECK(udp_packet_build(output, sizeof(output), &source, &destination, NULL, 0, 0, 64, &written) == UDP_PACKET_UNSUPPORTED);
    CHECK(!written);
    for (size_t i = 0; i < sizeof(output); ++i) CHECK(output[i] == 0xa5);
}

static void ingress_checksum_validation(void)
{
    unsigned char packet[256], corrupted[256];
    CHECK(!udp_packet_checksums_valid(NULL, 0));
    for (int v6 = 0; v6 < 2; ++v6) {
        const int family = v6 ? AF_INET6 : AF_INET;
        const size_t ip_size = v6 ? 40 : 20;
        struct udp_packet_endpoint source = endpoint(family, v6 ? "2001:db8::1" : "192.0.2.1", 5000);
        struct udp_packet_endpoint destination = endpoint(family, v6 ? "2001:db8::2" : "198.51.100.2", 6000);
        size_t size = 0;
        CHECK(udp_packet_build(packet, sizeof(packet), &source, &destination,
                               "odd payload", 11, 0, 64, &size) == UDP_PACKET_OK);
        CHECK(udp_packet_checksums_valid(packet, size));
        for (size_t length = 0; length < size; ++length)
            CHECK(!udp_packet_checksums_valid(packet, length));
        memcpy(corrupted, packet, size);
        corrupted[size - 1] ^= 1;
        CHECK(!udp_packet_checksums_valid(corrupted, size));
        memcpy(corrupted, packet, size);
        corrupted[ip_size + 6] ^= 1;
        CHECK(!udp_packet_checksums_valid(corrupted, size));
        memcpy(corrupted, packet, size);
        corrupted[ip_size + 6] = corrupted[ip_size + 7] = 0;
        CHECK(udp_packet_checksums_valid(corrupted, size) == !v6);
        if (!v6) {
            /* Header checksum validation still applies when UDP opts out. */
            corrupted[1] ^= 1;
            CHECK(!udp_packet_checksums_valid(corrupted, size));
            memcpy(corrupted, packet, size);
            corrupted[10] = corrupted[11] = 0;
            CHECK(!udp_packet_checksums_valid(corrupted, size));
            memcpy(corrupted, packet, size);
            corrupted[6] = 0x20;
        } else {
            memcpy(corrupted, packet, size);
            corrupted[6] = 44; /* No checksum approval for fragments. */
        }
        CHECK(!udp_packet_checksums_valid(corrupted, size));
    }
}

static uint32_t mutate_next(uint32_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

static void malformed_mutation_sweep(void)
{
    unsigned char original[256], mutated[256];
    uint32_t random = UINT32_C(0x729a51b3);
    struct udp_packet_view empty;
    memset(&empty, 0, sizeof(empty));
    for (int v6 = 0; v6 < 2; ++v6) {
        const int family = v6 ? AF_INET6 : AF_INET;
        struct udp_packet_endpoint source = endpoint(family, v6 ? "2001:db8::1" : "192.0.2.1", 40000);
        struct udp_packet_endpoint destination = endpoint(family, v6 ? "2001:db8::2" : "198.51.100.2", 40001);
        size_t original_length = 0;
        CHECK(udp_packet_build(original, sizeof(original), &source, &destination,
                               "deterministic parser mutation", 29, 0, 64,
                               &original_length) == UDP_PACKET_OK);
        for (unsigned int iteration = 0; iteration < 10000; ++iteration) {
            memset(mutated, 0xa5, sizeof(mutated));
            memcpy(mutated, original, original_length);
            const unsigned int flips = 1 + mutate_next(&random) % 3;
            for (unsigned int n = 0; n < flips; ++n) {
                size_t index = mutate_next(&random) % (original_length + 17);
                mutated[index] ^= (unsigned char)(1u << (mutate_next(&random) % 8));
            }
            const size_t length = iteration % 2 ? original_length :
                                   mutate_next(&random) % (original_length + 17);
            struct udp_packet_view view;
            memset(&view, 0x5a, sizeof(view));
            enum udp_packet_result result = udp_packet_parse(mutated, length, &view);
            if (result == UDP_PACKET_OK) {
                CHECK(view.payload >= mutated && view.payload <= mutated + length);
                CHECK(view.payload_length <= (size_t)(mutated + length - view.payload));
                CHECK(view.src.family == view.dst.family);
                CHECK(udp_packet_endpoint_valid(&view.src));
                CHECK(udp_packet_endpoint_valid(&view.dst));
            } else {
                CHECK(result == UDP_PACKET_INVALID || result == UDP_PACKET_UNSUPPORTED);
                CHECK(!memcmp(&view, &empty, sizeof(view)));
            }
            int valid = udp_packet_checksums_valid(mutated, length);
            CHECK(valid == 0 || valid == 1);
            CHECK(!valid || result == UDP_PACKET_OK);
        }
    }
}

int main(void)
{
    known_vectors();
    payload_boundaries();
    endpoints_and_wire();
    malformed_packets();
    build_rejections();
    ingress_checksum_validation();
    malformed_mutation_sweep();
    printf("PASS: UDP packet codec (%u checks), IPv4/IPv6 bounds, wire endpoints and independent checksums\n", checks);
    return 0;
}
