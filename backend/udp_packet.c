#include "udp_packet.h"

#include <sys/socket.h>
#include <string.h>

static uint16_t read_be16(const unsigned char *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static void write_be16(unsigned char *bytes, uint16_t value)
{
    bytes[0] = (unsigned char)(value >> 8);
    bytes[1] = (unsigned char)value;
}

static int all_zero(const unsigned char *bytes, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        if (bytes[i]) return 0;
    return 1;
}

int udp_packet_endpoint_valid(const struct udp_packet_endpoint *endpoint)
{
    if (!endpoint || !endpoint->port_net) return 0;
    const unsigned char *address = endpoint->address;
    if (endpoint->family == AF_INET) {
        return !all_zero(address, 4) && address[0] < 224 && address[0] != 0 &&
               !((address[0] & address[1] & address[2] & address[3]) == 255) &&
               all_zero(address + 4, 12);
    }
    if (endpoint->family != AF_INET6 || all_zero(address, 16) || address[0] == 0xff ||
        (address[0] == 0xfe && (address[1] & 0xc0) == 0x80))
        return 0;
    /* IPv4-mapped IPv6 sockets carry actual IPv4 wire packets. */
    if (all_zero(address, 10) && address[10] == 0xff && address[11] == 0xff)
        return 0;
    return 1;
}

enum udp_packet_result udp_packet_endpoint_from_wire(
    int family, const unsigned char wire[28], struct udp_packet_endpoint *endpoint)
{
    if (!endpoint) return UDP_PACKET_INVALID;
    memset(endpoint, 0, sizeof(*endpoint));
    if (!wire) return UDP_PACKET_INVALID;
    const unsigned int wire_family = wire[0] | ((unsigned int)wire[1] << 8);
    struct udp_packet_endpoint decoded = {0};
    decoded.family = family;
    if (family == AF_INET) {
        if (wire_family != 2) return UDP_PACKET_INVALID;
        if (!all_zero(wire + 8, 20)) return UDP_PACKET_UNSUPPORTED;
        memcpy(decoded.address, wire + 4, 4);
    } else if (family == AF_INET6) {
        if (wire_family != 23) return UDP_PACKET_INVALID;
        if (!all_zero(wire + 4, 4) || !all_zero(wire + 24, 4))
            return UDP_PACKET_UNSUPPORTED;
        memcpy(decoded.address, wire + 8, 16);
    } else {
        return UDP_PACKET_INVALID;
    }
    memcpy(&decoded.port_net, wire + 2, sizeof(decoded.port_net));
    if (!udp_packet_endpoint_valid(&decoded)) return UDP_PACKET_UNSUPPORTED;
    *endpoint = decoded;
    return UDP_PACKET_OK;
}

enum udp_packet_result udp_packet_parse(
    const void *packet, size_t length, struct udp_packet_view *view)
{
    if (!view) return UDP_PACKET_INVALID;
    memset(view, 0, sizeof(*view));
    if (!packet || !length) return UDP_PACKET_INVALID;
    const unsigned char *bytes = packet;
    size_t ip_length;
    struct udp_packet_view parsed = {0};
    if ((bytes[0] >> 4) == 4) {
        if (length < 20 || (bytes[0] & 15) < 5) return UDP_PACKET_INVALID;
        ip_length = (bytes[0] & 15u) * 4u;
        if (ip_length > length || read_be16(bytes + 2) != length)
            return UDP_PACKET_INVALID;
        if (ip_length != 20 || (read_be16(bytes + 6) & 0x3fffu))
            return UDP_PACKET_UNSUPPORTED;
        if (bytes[9] != 17) return UDP_PACKET_UNSUPPORTED;
        /* The reserved IPv4 flag cannot describe a valid ordinary packet. */
        if (read_be16(bytes + 6) & 0x8000u) return UDP_PACKET_INVALID;
        parsed.src.family = parsed.dst.family = AF_INET;
        memcpy(parsed.src.address, bytes + 12, 4);
        memcpy(parsed.dst.address, bytes + 16, 4);
        parsed.traffic_class = bytes[1];
        parsed.hop_limit = bytes[8];
    } else if ((bytes[0] >> 4) == 6) {
        if (length < 40) return UDP_PACKET_INVALID;
        ip_length = 40;
        const uint16_t declared = read_be16(bytes + 4);
        if (!declared) return UDP_PACKET_UNSUPPORTED; /* No jumbograms. */
        if ((size_t)declared + ip_length != length) return UDP_PACKET_INVALID;
        if (bytes[6] != 17) return UDP_PACKET_UNSUPPORTED;
        parsed.src.family = parsed.dst.family = AF_INET6;
        memcpy(parsed.src.address, bytes + 8, 16);
        memcpy(parsed.dst.address, bytes + 24, 16);
        parsed.traffic_class = (uint8_t)((bytes[0] << 4) | (bytes[1] >> 4));
        parsed.hop_limit = bytes[7];
    } else {
        return UDP_PACKET_INVALID;
    }
    if (length - ip_length < 8) return UDP_PACKET_INVALID;
    const unsigned char *udp = bytes + ip_length;
    if (read_be16(udp + 4) < 8 || read_be16(udp + 4) != length - ip_length)
        return UDP_PACKET_INVALID;
    memcpy(&parsed.src.port_net, udp, 2);
    memcpy(&parsed.dst.port_net, udp + 2, 2);
    if (!parsed.hop_limit || !udp_packet_endpoint_valid(&parsed.src) ||
        !udp_packet_endpoint_valid(&parsed.dst))
        return UDP_PACKET_UNSUPPORTED;
    parsed.payload = udp + 8;
    parsed.payload_length = length - ip_length - 8;
    *view = parsed;
    return UDP_PACKET_OK;
}

static uint32_t checksum_add(uint32_t sum, const unsigned char *bytes, size_t length)
{
    for (; length >= 2; bytes += 2, length -= 2)
        sum += ((uint32_t)bytes[0] << 8) | bytes[1];
    if (length) sum += (uint32_t)bytes[0] << 8;
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 65535u) + (sum >> 16);
    return (uint16_t)~sum;
}

int udp_packet_checksums_valid(const void *packet, size_t length)
{
    struct udp_packet_view view;
    if (udp_packet_parse(packet, length, &view) != UDP_PACKET_OK) return 0;
    const unsigned char *bytes = packet;
    const int v6 = view.src.family == AF_INET6;
    const size_t ip_length = v6 ? 40u : 20u;
    const unsigned char *udp = bytes + ip_length;
    if (!v6 && checksum_finish(checksum_add(0, bytes, ip_length)) != 0) return 0;
    if (read_be16(udp + 6) == 0) return !v6;
    const size_t address_length = v6 ? 16u : 4u;
    uint32_t sum = checksum_add(0, view.src.address, address_length);
    sum = checksum_add(sum, view.dst.address, address_length);
    sum += (uint32_t)(length - ip_length) + 17u;
    sum = checksum_add(sum, udp, length - ip_length);
    return checksum_finish(sum) == 0;
}

enum udp_packet_result udp_packet_build(
    void *buffer, size_t capacity,
    const struct udp_packet_endpoint *src, const struct udp_packet_endpoint *dst,
    const void *payload, size_t payload_length,
    uint8_t traffic_class, uint8_t hop_limit, size_t *written)
{
    if (!written) return UDP_PACKET_INVALID;
    *written = 0;
    if (!buffer || (!payload && payload_length) || !src || !dst ||
        src->family != dst->family)
        return UDP_PACKET_INVALID;
    if (!hop_limit || !udp_packet_endpoint_valid(src) || !udp_packet_endpoint_valid(dst))
        return UDP_PACKET_UNSUPPORTED;
    const int v6 = src->family == AF_INET6;
    const size_t ip_length = v6 ? 40u : 20u;
    const size_t max_payload = v6 ? UDP_PACKET_MAX_PAYLOAD_V6 : UDP_PACKET_MAX_PAYLOAD_V4;
    if (payload_length > max_payload) return UDP_PACKET_INVALID;
    const size_t udp_length = 8u + payload_length;
    const size_t total = ip_length + udp_length;
    if (capacity < total) return UDP_PACKET_CAPACITY;
    const struct udp_packet_endpoint source = *src, destination = *dst;
    unsigned char *bytes = buffer;
    /* Copy first so in-place payload edits cannot be destroyed by header reset. */
    if (payload_length) memmove(bytes + ip_length + 8, payload, payload_length);
    memset(bytes, 0, ip_length + 8);
    if (v6) {
        bytes[0] = (unsigned char)(0x60u | (traffic_class >> 4));
        bytes[1] = (unsigned char)(traffic_class << 4);
        write_be16(bytes + 4, (uint16_t)udp_length);
        bytes[6] = 17;
        bytes[7] = hop_limit;
        memcpy(bytes + 8, source.address, 16);
        memcpy(bytes + 24, destination.address, 16);
    } else {
        bytes[0] = 0x45;
        bytes[1] = traffic_class;
        write_be16(bytes + 2, (uint16_t)total);
        bytes[8] = hop_limit;
        bytes[9] = 17;
        memcpy(bytes + 12, source.address, 4);
        memcpy(bytes + 16, destination.address, 4);
        write_be16(bytes + 10, checksum_finish(checksum_add(0, bytes, 20)));
    }
    unsigned char *udp = bytes + ip_length;
    memcpy(udp, &source.port_net, 2);
    memcpy(udp + 2, &destination.port_net, 2);
    write_be16(udp + 4, (uint16_t)udp_length);
    uint32_t sum = 0;
    if (v6) {
        sum = checksum_add(sum, source.address, 16);
        sum = checksum_add(sum, destination.address, 16);
    } else {
        sum = checksum_add(sum, source.address, 4);
        sum = checksum_add(sum, destination.address, 4);
    }
    /* IPv6's 32-bit pseudoheader length has zero high bits for this subset;
       its three zero bytes and next-header contribute the same 17 word. */
    sum += (uint32_t)udp_length + 17u;
    sum = checksum_add(sum, udp, udp_length);
    uint16_t check = checksum_finish(sum);
    write_be16(udp + 6, check ? check : 65535u);
    *written = total;
    return UDP_PACKET_OK;
}
