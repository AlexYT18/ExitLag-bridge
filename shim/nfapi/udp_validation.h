// Freestanding UDP IPC and synchronous SDK argument validation.
#ifndef EXITLAG_SHIM_UDP_VALIDATION_H
#define EXITLAG_SHIM_UDP_VALIDATION_H

#include "../../backend/protocol.h"
#include "socket_attribution.h"

namespace exl_udp_validation {

static inline bool valid_local(unsigned long long tag, unsigned long long endpoint_id,
                                unsigned int process_id, unsigned int family,
                                const unsigned char *local)
{
    return tag && endpoint_id && process_id &&
        exl_socket_attribution::valid_endpoint(local, 28, family);
}

static inline bool valid_lifecycle(const exl_udp_lifecycle_req &request)
{
    return valid_local(request.tag, request.endpoint_id, request.process_id,
                       request.ip_family, request.local_address);
}

static inline bool valid_connect(const exl_udp_connect_req &request)
{
    return valid_local(request.tag, request.endpoint_id, request.process_id,
                       request.ip_family, request.local_address) &&
        exl_socket_attribution::valid_endpoint(request.remote_address, 28, request.ip_family);
}

static inline bool valid_datagram(const exl_udp_datagram_req &request,
                                   unsigned int frame_length)
{
    if (frame_length < sizeof(request) || frame_length > EXL_MAX_PAYLOAD ||
        !valid_local(request.tag, request.endpoint_id, request.process_id,
                      request.ip_family, request.local_address) ||
        !exl_socket_attribution::valid_endpoint(request.remote_address, 28, request.ip_family) ||
        (request.direction != EXL_DIR_IN && request.direction != EXL_DIR_OUT) ||
        request.reserved || request.options_length > 4096 || request.payload_length > 65535)
        return false;
    const unsigned int remaining = frame_length - (unsigned int)sizeof(request);
    return request.options_length <= remaining &&
        request.payload_length == remaining - request.options_length;
}

// Buffer may be NULL only for a real zero-length UDP datagram. Unsupported
// options are rejected, not silently presented as an empty options record.
static inline bool valid_post_arguments(const unsigned char *remote, const char *buffer,
                                         int length, long options_length)
{
    if (length < 0 || length > 65535 || (!buffer && length) ||
        options_length < 0 || options_length > 4096) return false;
    const unsigned int family = exl_socket_attribution::endpoint_family(remote, 28);
    return exl_socket_attribution::valid_endpoint(remote, 28, family);
}

// Copy only defined sockaddr fields. IPv4's eight padding bytes are neither
// routing metadata nor safe bytes to expose from an SDK caller's stack.
static inline bool canonical_post_remote(const unsigned char *source, size_t readable,
                                          unsigned char *destination, size_t capacity)
{
    if (!source || !destination || capacity < 28 || readable < 4) return false;
    const unsigned int family = exl_socket_attribution::endpoint_family(source, readable);
    const size_t meaningful = family == 2 ? 8u : family == 23 ? 28u : 0u;
    if (!meaningful || readable < meaningful || (!source[2] && !source[3])) return false;
    unsigned char temporary[28];
    for (size_t i = 0; i < 28; ++i) temporary[i] = i < meaningful ? source[i] : 0;
    for (size_t i = 0; i < 28; ++i) destination[i] = temporary[i];
    return true;
}

// This checks a calling thread's own active callback context. The caller must
// obtain that context from TLS, never a process-global current endpoint.
static inline bool context_matches(unsigned long long tag, unsigned long long endpoint_id,
                                    unsigned long long session, unsigned long long current_session,
                                    unsigned long long post_endpoint_id)
{
    return tag && endpoint_id && session && session == current_session &&
        endpoint_id == post_endpoint_id;
}

} // namespace exl_udp_validation

#endif // EXITLAG_SHIM_UDP_VALIDATION_H
