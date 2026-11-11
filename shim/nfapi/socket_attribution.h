// Freestanding Windows owner-table decoding shared by the PE shim and native tests.
#ifndef EXITLAG_SHIM_SOCKET_ATTRIBUTION_H
#define EXITLAG_SHIM_SOCKET_ATTRIBUTION_H

#include <stddef.h>

namespace exl_socket_attribution {

// Windows DWORD remains 32 bits in Win64. Native Linux unsigned long is 64 bits,
// so it must never describe an iphlpapi table in the portable tests or decoder.
typedef unsigned int u32;
typedef size_t size_type;
static_assert(sizeof(u32) == 4, "Windows owner-table DWORD must be 32 bits");

enum address_family { ipv4 = 2, ipv6 = 23 };
enum owner_status : unsigned int {
    owner_found, owner_none, owner_invalid, owner_ambiguous, owner_unavailable
};
struct owner_result { owner_status status; u32 pid; };

static inline owner_result result(owner_status status, u32 pid = 0)
{
    owner_result value = {status, pid};
    return value;
}

#pragma pack(push, 4)
struct tcp4_row {
    u32 state, local_address, local_port, remote_address, remote_port, owning_pid;
};
struct tcp6_row {
    unsigned char local_address[16];
    u32 local_scope, local_port;
    unsigned char remote_address[16];
    u32 remote_scope, remote_port, state, owning_pid;
};
struct udp4_row { u32 local_address, local_port, owning_pid; };
struct udp6_row {
    unsigned char local_address[16];
    u32 local_scope, local_port, owning_pid;
};
#pragma pack(pop)

// These assertions are compiled into both the production PE and native tests.
// Parsing below is bytewise: the table and the wire endpoints may be unaligned.
static_assert(sizeof(tcp4_row) == 24, "MIB_TCPROW_OWNER_PID layout changed");
static_assert(offsetof(tcp4_row, local_address) == 4 &&
              offsetof(tcp4_row, local_port) == 8 &&
              offsetof(tcp4_row, remote_address) == 12 &&
              offsetof(tcp4_row, remote_port) == 16 &&
              offsetof(tcp4_row, owning_pid) == 20, "TCP IPv4 field offsets changed");
static_assert(sizeof(tcp6_row) == 56, "MIB_TCP6ROW_OWNER_PID layout changed");
static_assert(offsetof(tcp6_row, local_scope) == 16 &&
              offsetof(tcp6_row, local_port) == 20 &&
              offsetof(tcp6_row, remote_address) == 24 &&
              offsetof(tcp6_row, remote_scope) == 40 &&
              offsetof(tcp6_row, remote_port) == 44 &&
              offsetof(tcp6_row, state) == 48 &&
              offsetof(tcp6_row, owning_pid) == 52, "TCP IPv6 field offsets changed");
static_assert(sizeof(udp4_row) == 12 && offsetof(udp4_row, owning_pid) == 8,
              "MIB_UDPROW_OWNER_PID layout changed");
static_assert(sizeof(udp6_row) == 28 && offsetof(udp6_row, local_scope) == 16 &&
              offsetof(udp6_row, local_port) == 20 &&
              offsetof(udp6_row, owning_pid) == 24,
              "MIB_UDP6ROW_OWNER_PID layout changed");

static inline u32 read_le32(const unsigned char *bytes)
{
    return (u32)bytes[0] | ((u32)bytes[1] << 8) |
           ((u32)bytes[2] << 16) | ((u32)bytes[3] << 24);
}

static inline unsigned int endpoint_family(const unsigned char *address,
                                           size_type length)
{
    return address && length >= 2 ?
        (unsigned int)address[0] | ((unsigned int)address[1] << 8) : 0;
}

static inline bool valid_endpoint(const unsigned char *address, size_type length,
                                  unsigned int family, bool require_port = true)
{
    size_type needed = family == ipv4 ? 16 : family == ipv6 ? 28 : 0;
    return needed && address && length >= needed &&
           endpoint_family(address, length) == family &&
           (!require_port || address[2] || address[3]);
}

static inline bool equal_bytes(const unsigned char *first, const unsigned char *second,
                               size_type count)
{
    for (size_type i = 0; i < count; ++i)
        if (first[i] != second[i]) return false;
    return true;
}

static inline bool zero_bytes(const unsigned char *bytes, size_type count)
{
    for (size_type i = 0; i < count; ++i)
        if (bytes[i]) return false;
    return true;
}

// GetExtended*Table reports the byte size through its DWORD in/out parameter.
// Check that size against the actual destination capacity before inspecting the
// count. Division avoids count*row_size overflow, including hostile UINT32_MAX.
// Extra bytes after complete rows are permitted (the API can include padding).
static inline bool valid_table(const void *table, size_type capacity,
                               size_type returned_size, size_type row_size,
                               u32 &count)
{
    if (!table || returned_size > capacity || returned_size < 4 || !row_size)
        return false;
    count = read_le32((const unsigned char *)table);
    return count <= (returned_size - 4) / row_size;
}

// MIB ports occupy the low two bytes of a DWORD in network byte order; the
// remaining two bytes are not part of the port. Wire sockaddr ports are at +2.
static inline bool same_port(const unsigned char *mib_port,
                             const unsigned char *endpoint)
{
    return mib_port[0] == endpoint[2] && mib_port[1] == endpoint[3];
}

// Preserve absence, malformed input and contradictory ownership as distinct
// outcomes so the caller does not treat corrupt/ambiguous tables as absence.
// Only connected TCP states SYN_SENT..LAST_ACK (3..10) may identify a live flow. CLOSED, LISTEN,
// TIME_WAIT and DELETE_TCB cannot provide ownership for a new connection; in
// particular TIME_WAIT rows can outlive the socket during source-tuple reuse.
static inline owner_result lookup_tcp_owner(const void *table, size_type capacity,
                                            size_type returned_size, unsigned int family,
                                            const unsigned char *local, size_type local_size,
                                            const unsigned char *remote, size_type remote_size)
{
    if (!valid_endpoint(local, local_size, family) ||
        !valid_endpoint(remote, remote_size, family)) return result(owner_invalid);
    const size_type row_size = family == ipv4 ? sizeof(tcp4_row) : sizeof(tcp6_row);
    u32 count;
    if (!valid_table(table, capacity, returned_size, row_size, count))
        return result(owner_invalid);
    const unsigned char *row = (const unsigned char *)table + 4;
    bool found = false;
    u32 pid = 0;
    for (u32 i = 0; i < count; ++i, row += row_size) {
        const u32 state = read_le32(row + (family == ipv4 ? 0 : 48));
        if (state < 3 || state > 10) continue;
        if (family == ipv4) {
            if (!same_port(row + 8, local) || !same_port(row + 16, remote) ||
                !equal_bytes(row + 4, local + 4, 4) ||
                !equal_bytes(row + 12, remote + 4, 4)) continue;
        } else {
            // Windows sockaddr_in6: family@0, port@2, flowinfo@4, address@8,
            // scope_id@24 (little endian). Flowinfo is not part of a TCP tuple.
            if (!same_port(row + 20, local) || !same_port(row + 44, remote) ||
                !equal_bytes(row, local + 8, 16) ||
                !equal_bytes(row + 24, remote + 8, 16) ||
                read_le32(row + 16) != read_le32(local + 24) ||
                read_le32(row + 40) != read_le32(remote + 24)) continue;
        }
        const u32 candidate = read_le32(row + (family == ipv4 ? 20 : 52));
        // Windows reports zero for rows with no attributable process. Such a
        // row is not ownership evidence and cannot identify or conflict a PID.
        if (!candidate) continue;
        if (found && candidate != pid) return result(owner_ambiguous);
        found = true;
        pid = candidate;
    }
    return found ? result(owner_found, pid) : result(owner_none);
}

// Convenience for callers that need only a PID. Production TCP callback policy
// uses lookup_tcp_owner's complete status and does not conflate these outcomes.
static inline u32 tcp_owner_pid(const void *table, size_type capacity,
                                size_type returned_size, unsigned int family,
                                const unsigned char *local, size_type local_size,
                                const unsigned char *remote, size_type remote_size)
{
    return lookup_tcp_owner(table, capacity, returned_size, family,
                            local, local_size, remote, remote_size).pid;
}

// The only cross-family representation accepted is an explicit IPv4-mapped
// IPv6 pair. It is useful when a dual-stack Windows socket's IPv4 traffic is
// listed in the IPv6 owner table. Both scopes/flowinfo are zero, and only the
// exact ::ffff:a.b.c.d form is constructed; mixed pairs and other aliases do
// not match. A failed conversion leaves the destination untouched.
static inline bool map_ipv4_endpoint(const unsigned char *source, size_type source_size,
                                     unsigned char *mapped, size_type mapped_size)
{
    if (!mapped || mapped_size < 28 || !valid_endpoint(source, source_size, ipv4))
        return false;
    unsigned char temporary[28];
    for (size_type i = 0; i < 28; ++i) temporary[i] = 0;
    temporary[0] = ipv6;
    temporary[2] = source[2]; temporary[3] = source[3];
    temporary[18] = temporary[19] = 0xff;
    for (size_type i = 0; i < 4; ++i) temporary[20 + i] = source[4 + i];
    for (size_type i = 0; i < 28; ++i) mapped[i] = temporary[i];
    return true;
}

static inline owner_result lookup_tcp_mapped_owner(const void *table, size_type capacity,
                                                   size_type returned_size,
                                                   const unsigned char *local, size_type local_size,
                                                   const unsigned char *remote, size_type remote_size)
{
    unsigned char mapped_local[28], mapped_remote[28];
    if (!map_ipv4_endpoint(local, local_size, mapped_local, sizeof(mapped_local)) ||
        !map_ipv4_endpoint(remote, remote_size, mapped_remote, sizeof(mapped_remote)))
        return result(owner_invalid);
    return lookup_tcp_owner(table, capacity, returned_size, ipv6,
                             mapped_local, sizeof(mapped_local),
                             mapped_remote, sizeof(mapped_remote));
}

static inline bool valid_result(const owner_result &value)
{
    switch (value.status) {
    case owner_found: return value.pid != 0;
    case owner_none: case owner_invalid: case owner_ambiguous: case owner_unavailable:
        return value.pid == 0;
    default: return false;
    }
}

// Merge only actual query results. Contradictory PIDs remain ambiguous even
// across tables; a malformed table cannot be concealed by a successful lookup.
static inline owner_result combine_tcp_owners(owner_result first, owner_result second)
{
    if (!valid_result(first) || !valid_result(second) ||
        first.status == owner_invalid || second.status == owner_invalid)
        return result(owner_invalid);
    if (first.status == owner_ambiguous || second.status == owner_ambiguous)
        return result(owner_ambiguous);
    if (first.status == owner_found && second.status == owner_found)
        return first.pid == second.pid ? first : result(owner_ambiguous);
    if (first.status == owner_found) return first;
    if (second.status == owner_found) return second;
    if (first.status == owner_unavailable || second.status == owner_unavailable)
        return result(owner_unavailable);
    return result(owner_none);
}

// Windows UDP owner tables do not expose the connected remote peer. Every
// compatible local bind therefore contributes evidence; exact/ANY overlap must
// not hide another PID. PID zero is an unattributable matching row, not absence.
static inline owner_result lookup_udp_owner(const void *table, size_type capacity,
                                            size_type returned_size, unsigned int family,
                                            const unsigned char *local, size_type local_size)
{
    if (!valid_endpoint(local, local_size, family)) return result(owner_invalid);
    const size_type row_size = family == ipv4 ? sizeof(udp4_row) : sizeof(udp6_row);
    u32 count;
    if (!valid_table(table, capacity, returned_size, row_size, count)) return result(owner_invalid);
    const unsigned char *row = (const unsigned char *)table + 4;
    bool found = false, unknown_mapped_any = false, ambiguous = false, invalid_owner = false;
    u32 pid = 0;
    for (u32 i = 0; i < count; ++i, row += row_size) {
        const size_type port_offset = family == ipv4 ? 4 : 20;
        const size_type address_offset = family == ipv4 ? 4 : 8;
        const size_type address_size = family == ipv4 ? 4 : 16;
        if (!same_port(row + port_offset, local)) continue;
        const bool any = zero_bytes(row, address_size);
        if (!any && !equal_bytes(row, local + address_offset, address_size)) continue;
        if (family == ipv6) {
            const u32 scope = read_le32(row + 16);
            const u32 wanted_scope = read_le32(local + 24);
            if (any ? (scope && scope != wanted_scope) : scope != wanted_scope) continue;
            // A UDP6 ANY row might be IPV6_V6ONLY. The owner table cannot
            // establish that it owns IPv4 traffic, so never guess that PID.
            if (any && zero_bytes(local + 8, 10) &&
                local[18] == 0xff && local[19] == 0xff)
                unknown_mapped_any = true;
        }
        const u32 candidate = read_le32(row + (family == ipv4 ? 8 : 24));
        if (!candidate) { invalid_owner = true; continue; }
        if (found && candidate != pid) ambiguous = true;
        found = true;
        pid = candidate;
    }
    if (invalid_owner) return result(owner_invalid);
    if (unknown_mapped_any || ambiguous) return result(owner_ambiguous);
    return found ? result(owner_found, pid) : result(owner_none);
}

static inline u32 udp_owner_pid(const void *table, size_type capacity,
                                size_type returned_size, unsigned int family,
                                const unsigned char *local, size_type local_size)
{
    return lookup_udp_owner(table, capacity, returned_size, family, local, local_size).pid;
}

static inline owner_result lookup_udp_mapped_owner(const void *table, size_type capacity,
                                                   size_type returned_size,
                                                   const unsigned char *local, size_type local_size)
{
    unsigned char mapped_local[28];
    if (!map_ipv4_endpoint(local, local_size, mapped_local, sizeof(mapped_local)))
        return result(owner_invalid);
    return lookup_udp_owner(table, capacity, returned_size, ipv6,
                            mapped_local, sizeof(mapped_local));
}

} // namespace exl_socket_attribution

#endif // EXITLAG_SHIM_SOCKET_ATTRIBUTION_H
