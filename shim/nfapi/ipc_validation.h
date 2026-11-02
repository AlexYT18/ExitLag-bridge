// Freestanding IPC validation shared by the PE shim and native regression tests.
#ifndef EXITLAG_SHIM_IPC_VALIDATION_H
#define EXITLAG_SHIM_IPC_VALIDATION_H

#include "../../backend/protocol.h"

// The Linux and Windows builds must consume identical packed wire records.
static_assert(sizeof(exl_header) == 12, "IPC header layout changed");
static_assert(sizeof(exl_hello) == 48, "IPC hello layout changed");
static_assert(sizeof(exl_hello_ack) == 16, "IPC hello ack layout changed");
static_assert(sizeof(exl_tcp_connect_req) == 86, "IPC TCP request layout changed");
static_assert(sizeof(exl_tcp_connect_reply) == 48, "IPC TCP reply layout changed");
static_assert(sizeof(exl_resolve_pid_req) == 16, "IPC PID request layout changed");
static_assert(sizeof(exl_resolve_pid_reply) == 16, "IPC PID reply layout changed");
static_assert(sizeof(exl_udp_lifecycle_req) == 50, "IPC UDP lifecycle request layout changed");
static_assert(sizeof(exl_udp_lifecycle_reply) == 50, "IPC UDP lifecycle reply layout changed");
static_assert(sizeof(exl_udp_connect_req) == 82, "IPC UDP connect request layout changed");
static_assert(sizeof(exl_udp_connect_reply) == 52, "IPC UDP connect reply layout changed");
static_assert(sizeof(exl_udp_datagram_req) == 92, "IPC UDP datagram request layout changed");
static_assert(sizeof(exl_udp_datagram_reply) == 28, "IPC UDP datagram reply layout changed");
static_assert(sizeof(exl_udp_post) == 64, "IPC UDP post layout changed");
static_assert(sizeof(exl_udp_state) == 32, "IPC UDP state layout changed");

namespace exl_ipc_validation {

static inline bool parse_decimal(const wchar_t *&cursor, unsigned int limit,
                                 unsigned int &value)
{
    if (*cursor < L'0' || *cursor > L'9') return false;
    value = 0;
    do {
        unsigned int digit = (unsigned int)(*cursor - L'0');
        // Test the bound before multiplication, including arbitrarily long input.
        if (value > limit / 10 || (value == limit / 10 && digit > limit % 10))
            return false;
        value = value * 10 + digit;
        ++cursor;
    } while (*cursor >= L'0' && *cursor <= L'9');
    return true;
}

// Accept only numeric IPv4 loopback, with an optional port (default 51900).
// The session token must never be sent to an off-host endpoint by configuration.
// The caller supplies a 16-byte Windows sockaddr_in; failure leaves it untouched.
static inline bool parse_loopback_endpoint(const wchar_t *text, unsigned char *address)
{
    if (!text || !address) return false;
    const wchar_t *cursor = text;
    unsigned int octets[4];
    for (unsigned int i = 0; i < 4; ++i) {
        if (!parse_decimal(cursor, 255, octets[i])) return false;
        if (i != 3) {
            if (*cursor != L'.') return false;
            ++cursor;
        }
    }
    if (octets[0] != 127) return false;
    unsigned int port = EXL_DEFAULT_PORT;
    if (*cursor == L':') {
        ++cursor;
        if (!parse_decimal(cursor, 65535, port) || !port) return false;
    }
    if (*cursor) return false;

    for (unsigned int i = 0; i < 16; ++i) address[i] = 0;
    address[0] = 2; // Windows AF_INET.
    address[2] = (unsigned char)(port >> 8);
    address[3] = (unsigned char)port;
    for (unsigned int i = 0; i < 4; ++i) address[4 + i] = (unsigned char)octets[i];
    return true;
}

static inline bool valid_frame_header(const exl_header &header)
{
    return header.magic == EXL_MAGIC && header.flags == 0 &&
           header.length <= EXL_MAX_PAYLOAD;
}

// Validate the entire variable-size reply before reading a path byte or writing
// the caller's buffer. Retain the existing byte-widening/truncation semantics;
// proper UTF-8 decoding is a separate compatibility change.
static inline bool copy_pid_reply_path(const exl_resolve_pid_reply &reply,
                                      const char *frame, unsigned int frame_length,
                                      wchar_t *buffer, unsigned long capacity)
{
    if (!frame || !buffer || !capacity || reply.reserved ||
        frame_length < sizeof(reply) || frame_length > EXL_MAX_PAYLOAD ||
        !reply.path_length || reply.path_length != frame_length - sizeof(reply))
        return false;
    unsigned int count = reply.path_length;
    if (count > capacity - 1) count = (unsigned int)(capacity - 1);
    const char *path = frame + sizeof(reply);
    for (unsigned int i = 0; i < count; ++i) buffer[i] = (wchar_t)(unsigned char)path[i];
    buffer[count] = 0;
    return true;
}

} // namespace exl_ipc_validation

#endif // EXITLAG_SHIM_IPC_VALIDATION_H
