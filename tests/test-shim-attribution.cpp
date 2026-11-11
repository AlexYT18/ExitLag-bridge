// No Wine, account, sockets or Windows headers: test the production decoder
// against manually encoded Windows MIB table bytes, including on native LP64.
#include "../shim/nfapi/socket_attribution.h"
#include "../shim/nfapi/udp_validation.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace attribution = exl_socket_attribution;
using Bytes = std::vector<unsigned char>;
using Endpoint = std::array<unsigned char, 28>;
static unsigned int checks;

static void require(bool condition, const char *message)
{
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

static void put32(unsigned char *where, unsigned int value)
{
    for (unsigned int i = 0; i != 4; ++i)
        where[i] = (unsigned char)(value >> (i * 8));
}

static Endpoint endpoint4(unsigned int final_octet, unsigned int port)
{
    Endpoint e = {{2, 0, (unsigned char)(port >> 8), (unsigned char)port,
                   192, 0, 2, (unsigned char)final_octet}};
    return e;
}

static Endpoint endpoint6(unsigned int final_octet, unsigned int port,
                          unsigned int scope = 0)
{
    Endpoint e = {{23, 0, (unsigned char)(port >> 8), (unsigned char)port}};
    e[8] = 0xfe; e[9] = 0x80; e[23] = (unsigned char)final_octet;
    put32(e.data() + 24, scope);
    return e;
}

static Bytes tcp4(const Endpoint &local, const Endpoint &remote,
                  unsigned int pid, unsigned int state = 5)
{
    Bytes r(24, 0);
    put32(r.data(), state);
    std::memcpy(r.data() + 4, local.data() + 4, 4);
    std::memcpy(r.data() + 8, local.data() + 2, 2);
    std::memcpy(r.data() + 12, remote.data() + 4, 4);
    std::memcpy(r.data() + 16, remote.data() + 2, 2);
    put32(r.data() + 20, pid);
    return r;
}

static Bytes tcp6(const Endpoint &local, const Endpoint &remote,
                  unsigned int pid, unsigned int state = 5)
{
    Bytes r(56, 0);
    std::memcpy(r.data(), local.data() + 8, 16);
    std::memcpy(r.data() + 16, local.data() + 24, 4);
    std::memcpy(r.data() + 20, local.data() + 2, 2);
    std::memcpy(r.data() + 24, remote.data() + 8, 16);
    std::memcpy(r.data() + 40, remote.data() + 24, 4);
    std::memcpy(r.data() + 44, remote.data() + 2, 2);
    put32(r.data() + 48, state);
    put32(r.data() + 52, pid);
    return r;
}

struct TcpRows {
    unsigned int family;
    Bytes operator()(const Endpoint &local, const Endpoint &remote,
                     unsigned int pid, unsigned int state = 5) const
    {
        return family == 2 ? tcp4(local, remote, pid, state) :
                             tcp6(local, remote, pid, state);
    }
};

static Bytes udp4(const Endpoint &local, unsigned int pid)
{
    Bytes r(12, 0);
    std::memcpy(r.data(), local.data() + 4, 4);
    std::memcpy(r.data() + 4, local.data() + 2, 2);
    put32(r.data() + 8, pid);
    return r;
}

static Bytes udp6(const Endpoint &local, unsigned int pid)
{
    Bytes r(28, 0);
    std::memcpy(r.data(), local.data() + 8, 16);
    std::memcpy(r.data() + 16, local.data() + 24, 4);
    std::memcpy(r.data() + 20, local.data() + 2, 2);
    put32(r.data() + 24, pid);
    return r;
}

static Bytes table(std::initializer_list<Bytes> rows)
{
    Bytes t(4, 0);
    put32(t.data(), (unsigned int)rows.size());
    for (const Bytes &row : rows) t.insert(t.end(), row.begin(), row.end());
    return t;
}

static unsigned int owner(const Bytes &t, const Endpoint &local,
                          const Endpoint &remote, unsigned int family)
{
    return attribution::tcp_owner_pid(t.data(), t.size(), t.size(), family,
                                      local.data(), local.size(),
                                      remote.data(), remote.size());
}

static unsigned int udp_owner(const Bytes &t, const Endpoint &local,
                              unsigned int family)
{
    return attribution::udp_owner_pid(t.data(), t.size(), t.size(), family,
                                      local.data(), local.size());
}

static void tcp_tuple_tests(unsigned int family)
{
    Endpoint local = family == 2 ? endpoint4(10, 49153) : endpoint6(10, 49153, 7);
    Endpoint remote = family == 2 ? endpoint4(80, 443) : endpoint6(80, 443, 8);
    const TcpRows row = {family};
    Bytes exact = table({row(local, remote, 0x12345678)});
    require(owner(exact, local, remote, family) == 0x12345678,
            "exact TCP tuple lost its Windows PID");

    // The same local address and port with another remote peer must never
    // attribute the observed flow to that peer's owner, regardless of order.
    Endpoint other_remote = remote;
    other_remote[family == 2 ? 7 : 23] ^= 1;
    Bytes collision = table({row(local, other_remote, 111), row(local, remote, 222)});
    require(owner(collision, local, remote, family) == 222,
            "first local-tuple collision won over exact remote address");
    collision = table({row(local, remote, 222), row(local, other_remote, 111)});
    require(owner(collision, local, remote, family) == 222,
            "later local-tuple collision changed exact remote match");
    other_remote = remote; other_remote[3] ^= 1;
    require(owner(table({row(local, other_remote, 111), row(local, remote, 222)}),
                  local, remote, family) == 222, "remote port was ignored");

    // Mutate every address and port byte individually. Flowinfo and sockaddr
    // padding are deliberately outside the socket identity.
    const unsigned int address_start = family == 2 ? 4 : 8;
    const unsigned int address_end = family == 2 ? 8 : 24;
    for (unsigned int byte = 2; byte < address_end; ++byte) {
        if (byte >= 4 && byte < address_start) continue;
        Endpoint changed = local; changed[byte] ^= 0x40;
        require(owner(exact, changed, remote, family) == 0,
                "local address/port byte was ignored");
        changed = remote; changed[byte] ^= 0x40;
        require(owner(exact, local, changed, family) == 0,
                "remote address/port byte was ignored");
    }
    if (family == 23) {
        for (unsigned int byte = 24; byte != 28; ++byte) {
            Endpoint changed = local; changed[byte] ^= 0x40;
            require(owner(exact, changed, remote, family) == 0, "local IPv6 scope ignored");
            changed = remote; changed[byte] ^= 0x40;
            require(owner(exact, local, changed, family) == 0, "remote IPv6 scope ignored");
        }
        Endpoint changed_local = local, changed_remote = remote;
        std::memset(changed_local.data() + 4, 0xff, 4);
        std::memset(changed_remote.data() + 4, 0xa5, 4);
        require(owner(exact, changed_local, changed_remote, family) == 0x12345678,
                "IPv6 flowinfo was used as socket identity");
    } else {
        Endpoint changed_local = local, changed_remote = remote;
        std::memset(changed_local.data() + 8, 0xff, 20);
        std::memset(changed_remote.data() + 8, 0xa5, 20);
        require(owner(exact, changed_local, changed_remote, family) == 0x12345678,
                "IPv4 padding was used as socket identity");
    }

    require(owner(table({row(local, remote, 9), row(local, remote, 9)}),
                  local, remote, family) == 9, "same-owner duplicate became ambiguous");
    require(owner(table({row(local, remote, 9), row(local, remote, 10)}),
                  local, remote, family) == 0, "different-owner duplicate was accepted");
    require(owner(table({row(local, remote, 10), row(local, remote, 9)}),
                  local, remote, family) == 0, "ambiguity depended on row order");
    require(owner(table({row(local, remote, 0), row(local, remote, 9)}),
                  local, remote, family) == 9, "zero-owner row hid a valid TCP owner");
    require(owner(table({row(local, remote, 9), row(local, remote, 0)}),
                  local, remote, family) == 9, "later zero-owner row hid a valid TCP owner");

    for (unsigned int state = 0; state <= 13; ++state) {
        unsigned int expected = state >= 3 && state <= 10 ? 900 : 0;
        require(owner(table({row(local, remote, 900, state)}), local, remote, family) == expected,
                "TCP state eligibility differs from SYN_SENT through LAST_ACK");
    }
    require(owner(table({row(local, remote, 55, 2), row(local, remote, 66, 5)}),
                  local, remote, family) == 66, "listener polluted exact connection match");
    require(owner(table({row(local, remote, 55, 1), row(local, remote, 66, 5)}),
                  local, remote, family) == 66, "closed entry polluted exact connection match");
    require(owner(table({row(local, remote, 55, 11), row(local, remote, 66, 5)}),
                  local, remote, family) == 66, "TIME_WAIT entry polluted reused tuple match");

    Endpoint zero_port = local; zero_port[2] = zero_port[3] = 0;
    require(owner(table({row(zero_port, remote, 4)}), zero_port, remote, family) == 0,
            "zero local TCP port accepted");
    zero_port = remote; zero_port[2] = zero_port[3] = 0;
    require(owner(table({row(local, zero_port, 4)}), local, zero_port, family) == 0,
            "zero remote TCP port accepted");

    const unsigned int minimum = family == 2 ? 16 : 28;
    for (unsigned int n = 0; n != minimum; ++n) {
        require(attribution::tcp_owner_pid(exact.data(), exact.size(), exact.size(), family,
                 local.data(), n, remote.data(), remote.size()) == 0,
                "short local sockaddr accepted");
        require(attribution::tcp_owner_pid(exact.data(), exact.size(), exact.size(), family,
                 local.data(), local.size(), remote.data(), n) == 0,
                "short remote sockaddr accepted");
    }
    Endpoint wrong = local; wrong[0] = family == 2 ? 23 : 2;
    require(owner(exact, wrong, remote, family) == 0, "wrong local family accepted");
    wrong = remote; wrong[1] = 1;
    require(owner(exact, local, wrong, family) == 0, "wrong remote family accepted");
    require(owner(exact, local, remote, 0) == 0, "unsupported TCP family accepted");
    require(attribution::tcp_owner_pid(exact.data(), exact.size(), exact.size(), family,
             nullptr, local.size(), remote.data(), remote.size()) == 0,
            "null local sockaddr accepted");
    require(attribution::tcp_owner_pid(exact.data(), exact.size(), exact.size(), family,
             local.data(), local.size(), nullptr, remote.size()) == 0,
            "null remote sockaddr accepted");

    for (unsigned int n = 0; n < exact.size(); ++n) {
        Bytes shortened(exact.begin(), exact.begin() + n);
        require(owner(shortened, local, remote, family) == 0, "truncated TCP table accepted");
        require(attribution::tcp_owner_pid(exact.data(), exact.size(), n, family,
                 local.data(), local.size(), remote.data(), remote.size()) == 0,
                "TCP decoder read complete row beyond API returned span");
    }
    require(attribution::tcp_owner_pid(exact.data(), exact.size() - 1, exact.size(), family,
             local.data(), local.size(), remote.data(), remote.size()) == 0,
            "TCP returned size beyond buffer capacity accepted");
    require(attribution::tcp_owner_pid(exact.data(), exact.size(), 3, family,
             local.data(), local.size(), remote.data(), remote.size()) == 0,
            "TCP decoder read beyond API returned size");
    require(attribution::tcp_owner_pid(nullptr, exact.size(), exact.size(), family,
             local.data(), local.size(), remote.data(), remote.size()) == 0,
            "null TCP table accepted");
    for (unsigned int count : {2u, 0x10000000u, 0x80000000u, 0xffffffffu}) {
        Bytes invalid = exact; put32(invalid.data(), count);
        require(owner(invalid, local, remote, family) == 0, "oversized TCP row count accepted");
    }
    Bytes empty(4, 0);
    require(owner(empty, local, remote, family) == 0, "empty TCP table attributed owner");
    Bytes padded = exact; padded.insert(padded.end(), 7, 0xa5);
    require(owner(padded, local, remote, family) == 0x12345678,
            "API buffer trailing padding rejected");
    Bytes unaligned(1, 0xa5); unaligned.insert(unaligned.end(), exact.begin(), exact.end());
    require(attribution::tcp_owner_pid(unaligned.data() + 1, exact.size(), exact.size(), family,
             local.data(), local.size(), remote.data(), remote.size()) == 0x12345678,
            "unaligned TCP table decoded incorrectly");
    // DWORD ports contain their network-order port in the first two bytes.
    Bytes upper_bits = exact;
    const unsigned int local_port = family == 2 ? 8 : 20;
    const unsigned int remote_port = family == 2 ? 16 : 44;
    upper_bits[4 + local_port + 2] = upper_bits[4 + local_port + 3] = 0xff;
    upper_bits[4 + remote_port + 2] = upper_bits[4 + remote_port + 3] = 0xff;
    require(owner(upper_bits, local, remote, family) == 0x12345678,
            "unused MIB port DWORD upper bits changed port identity");
}

static void udp_bounds_and_ownership(unsigned int family)
{
    Endpoint local = family == 2 ? endpoint4(10, 5353) : endpoint6(10, 5353, 7);
    Endpoint wildcard = local;
    std::memset(wildcard.data() + (family == 2 ? 4 : 8), 0, family == 2 ? 4 : 16);
    auto row = [family](const Endpoint &a, unsigned int pid) {
        return family == 2 ? udp4(a, pid) : udp6(a, pid);
    };
    Bytes exact = table({row(local, 123)});
    require(udp_owner(exact, local, family) == 123, "exact UDP local endpoint lost owner");
    require(udp_owner(table({row(wildcard, 10), row(local, 20), row(local, 30)}),
                      local, family) == 0, "UDP conflicting exact/wildcard owners accepted");
    require(udp_owner(table({row(wildcard, 10), row(wildcard, 30)}),
                      local, family) == 0, "UDP conflicting wildcard owners accepted");
    require(udp_owner(table({row(wildcard, 10), row(local, 10)}), local, family) == 10,
            "UDP same-owner exact/wildcard duplicate became ambiguous");
    require(udp_owner(table({row(local, 10), row(wildcard, 30)}), local, family) == 0,
            "UDP ambiguity depended on exact row being first");
    Endpoint zero_port = local; zero_port[2] = zero_port[3] = 0;
    require(udp_owner(table({row(zero_port, 41)}), zero_port, family) == 0,
            "UDP zero-port lookup accepted");
    Endpoint another = local; another[family == 2 ? 7 : 23] ^= 1;
    require(udp_owner(table({row(another, 99)}), local, family) == 0,
            "UDP wrong local address matched");
    another = local; another[3] ^= 1;
    require(udp_owner(table({row(another, 99)}), local, family) == 0,
            "UDP wrong local port matched");
    if (family == 23) {
        another = local; another[24] ^= 1;
        require(udp_owner(table({row(another, 99)}), local, family) == 0,
                "UDP scope was ignored");
        Endpoint any_scope = wildcard;
        put32(any_scope.data() + 24, 0);
        require(udp_owner(table({row(any_scope, 99)}), local, family) == 99,
                "UDP unscoped ANY bind did not match scoped local endpoint");
        put32(any_scope.data() + 24, 8);
        require(udp_owner(table({row(any_scope, 99)}), local, family) == 0,
                "UDP wrong scoped ANY bind matched");
    }
    for (unsigned int n = 0; n < exact.size(); ++n) {
        Bytes shortened(exact.begin(), exact.begin() + n);
        require(udp_owner(shortened, local, family) == 0, "truncated UDP table accepted");
        require(attribution::udp_owner_pid(exact.data(), exact.size(), n, family,
                 local.data(), local.size()) == 0,
                "UDP decoder read complete row beyond API returned span");
    }
    for (unsigned int count : {2u, 0x10000000u, 0x80000000u, 0xffffffffu}) {
        Bytes invalid = exact; put32(invalid.data(), count);
        require(udp_owner(invalid, local, family) == 0, "oversized UDP row count accepted");
    }
    require(attribution::udp_owner_pid(exact.data(), exact.size() - 1, exact.size(), family,
             local.data(), local.size()) == 0, "UDP returned size exceeded capacity");
    require(attribution::udp_owner_pid(exact.data(), exact.size(), 3, family,
             local.data(), local.size()) == 0, "UDP decoder ignored API returned size");
    require(attribution::udp_owner_pid(nullptr, exact.size(), exact.size(), family,
             local.data(), local.size()) == 0, "null UDP table accepted");
    require(attribution::udp_owner_pid(exact.data(), exact.size(), exact.size(), family,
             nullptr, local.size()) == 0, "null UDP sockaddr accepted");
    const unsigned int minimum = family == 2 ? 16 : 28;
    for (unsigned int n = 0; n < minimum; ++n)
        require(attribution::udp_owner_pid(exact.data(), exact.size(), exact.size(), family,
                 local.data(), n) == 0, "short UDP sockaddr accepted");
    Endpoint wrong = local; wrong[1] = 1;
    require(udp_owner(exact, wrong, family) == 0, "wrong UDP sockaddr family accepted");
    require(udp_owner(exact, local, 0) == 0, "unsupported UDP family accepted");
    Bytes unaligned(1, 0xa5); unaligned.insert(unaligned.end(), exact.begin(), exact.end());
    require(attribution::udp_owner_pid(unaligned.data() + 1, exact.size(), exact.size(), family,
             local.data(), local.size()) == 123, "unaligned UDP table decoded incorrectly");
}

static attribution::owner_result result(const Bytes &t, const Endpoint &local,
                                         const Endpoint &remote, unsigned int family)
{
    return attribution::lookup_tcp_owner(t.data(), t.size(), t.size(), family,
                                         local.data(), local.size(),
                                         remote.data(), remote.size());
}

static void expect_result(attribution::owner_result value,
                           attribution::owner_status expected, unsigned int pid,
                           const char *message)
{
    require(value.status == expected && value.pid == pid, message);
}

static void tcp_result_tests(unsigned int family)
{
    Endpoint local = family == 2 ? endpoint4(11, 40000) : endpoint6(11, 40000, 7);
    Endpoint remote = family == 2 ? endpoint4(90, 443) : endpoint6(90, 443, 8);
    const TcpRows row = {family};
    Bytes exact = table({row(local, remote, 301)});
    expect_result(result(exact, local, remote, family), attribution::owner_found, 301,
                  "exact TCP result did not distinguish FOUND");
    expect_result(result(table({}), local, remote, family), attribution::owner_none, 0,
                  "empty valid TCP table did not distinguish NONE");
    Endpoint wrong = remote; wrong[3] ^= 1;
    expect_result(result(exact, local, wrong, family), attribution::owner_none, 0,
                  "unmatched TCP tuple did not distinguish NONE");
    expect_result(result(table({row(local, remote, 0), row(local, remote, 0)}),
                         local, remote, family), attribution::owner_none, 0,
                  "all PID0 TCP rows did not yield NONE");
    expect_result(result(table({row(local, remote, 0), row(local, remote, 301)}),
                         local, remote, family), attribution::owner_found, 301,
                  "PID0 row polluted FOUND result");
    expect_result(result(table({row(local, remote, 301), row(local, remote, 302)}),
                         local, remote, family), attribution::owner_ambiguous, 0,
                  "conflicting TCP owners did not distinguish AMBIGUOUS");
    expect_result(result(table({row(local, remote, 301, 11)}), local, remote, family),
                  attribution::owner_none, 0, "ineligible state did not yield NONE");
    for (unsigned int n = 0; n < exact.size(); ++n)
        expect_result(attribution::lookup_tcp_owner(exact.data(), exact.size(), n, family,
                         local.data(), local.size(), remote.data(), remote.size()),
                      attribution::owner_invalid, 0,
                      "truncated API span did not distinguish INVALID");
    Bytes bad_count = exact; put32(bad_count.data(), 0xffffffffu);
    expect_result(result(bad_count, local, remote, family), attribution::owner_invalid, 0,
                  "overflowing TCP count did not distinguish INVALID");
    expect_result(attribution::lookup_tcp_owner(exact.data(), exact.size() - 1,
                     exact.size(), family, local.data(), local.size(),
                     remote.data(), remote.size()), attribution::owner_invalid, 0,
                  "returned size beyond capacity did not yield INVALID");
    expect_result(attribution::lookup_tcp_owner(nullptr, exact.size(), exact.size(), family,
                     local.data(), local.size(), remote.data(), remote.size()),
                  attribution::owner_invalid, 0, "null table did not yield INVALID");
    expect_result(attribution::lookup_tcp_owner(exact.data(), exact.size(), exact.size(),
                     family, nullptr, local.size(), remote.data(), remote.size()),
                  attribution::owner_invalid, 0, "null endpoint did not yield INVALID");
    expect_result(attribution::lookup_tcp_owner(exact.data(), exact.size(), exact.size(),
                     family, local.data(), 1, remote.data(), remote.size()),
                  attribution::owner_invalid, 0, "short endpoint did not yield INVALID");
    expect_result(result(exact, local, remote, 0), attribution::owner_invalid, 0,
                  "unknown family did not yield INVALID");
    wrong = remote; wrong[1] = 1;
    expect_result(result(exact, local, wrong, family), attribution::owner_invalid, 0,
                  "mixed endpoint family did not yield INVALID");
}

// Construct expected ::ffff addresses directly, independently of the mapper.
static Endpoint expected_mapped(const Endpoint &source)
{
    Endpoint mapped = {{23, 0, source[2], source[3]}};
    mapped[18] = mapped[19] = 0xff;
    std::memcpy(mapped.data() + 20, source.data() + 4, 4);
    return mapped;
}

static attribution::owner_result mapped_result(const Bytes &t,
                                                const Endpoint &local,
                                                const Endpoint &remote)
{
    return attribution::lookup_tcp_mapped_owner(t.data(), t.size(), t.size(),
              local.data(), local.size(), remote.data(), remote.size());
}

static void mapped_endpoint_tests()
{
    const Endpoint local = endpoint4(11, 49153), remote = endpoint4(90, 443);
    const Endpoint mapped_local = expected_mapped(local), mapped_remote = expected_mapped(remote);
    Endpoint actual; actual.fill(0xa5);
    require(attribution::map_ipv4_endpoint(local.data(), local.size(), actual.data(), actual.size()),
            "valid IPv4 endpoint failed mapping");
    require(actual == mapped_local, "mapped address/port/flowinfo/scope differs from wire format");
    actual.fill(0xa5);
    require(attribution::map_ipv4_endpoint(remote.data(), 16, actual.data(), actual.size()),
            "minimum-sized IPv4 endpoint failed mapping");
    require(actual == mapped_remote, "remote IPv4 endpoint mapping lost address or port");
    Endpoint dirty_source = local;
    std::memset(dirty_source.data() + 8, 0xff, 20);
    require(attribution::map_ipv4_endpoint(dirty_source.data(), dirty_source.size(),
                                            actual.data(), actual.size()),
            "IPv4 sockaddr padding prevented mapping");
    require(actual == mapped_local, "IPv4 padding leaked into mapped flowinfo or scope");
    actual = local;
    require(attribution::map_ipv4_endpoint(actual.data(), actual.size(),
                                            actual.data(), actual.size()),
            "in-place mapping rejected overlapping source and destination");
    require(actual == mapped_local, "in-place mapping corrupted source address or port");
    std::array<unsigned char, 30> guarded; guarded.fill(0xa5);
    require(attribution::map_ipv4_endpoint(local.data(), local.size(), guarded.data() + 1, 28),
            "mapping with guarded output failed");
    require(guarded.front() == 0xa5 && guarded.back() == 0xa5,
            "mapping wrote outside its 28-byte output");

    // Failure must not expose a partially rewritten output endpoint.
    for (unsigned int n = 0; n < 16; ++n) {
        actual.fill(0xa5); const Endpoint before = actual;
        require(!attribution::map_ipv4_endpoint(local.data(), n, actual.data(), actual.size()),
                "short source endpoint mapped");
        require(actual == before, "short source mapping changed output");
    }
    for (unsigned int n = 0; n < 28; ++n) {
        actual.fill(0xa5); const Endpoint before = actual;
        require(!attribution::map_ipv4_endpoint(local.data(), local.size(), actual.data(), n),
                "short destination endpoint mapped");
        require(actual == before, "short destination mapping changed output");
    }
    for (Endpoint invalid : {endpoint6(11, 49153), Endpoint{{0}}, endpoint4(11, 0)}) {
        actual.fill(0xa5); const Endpoint before = actual;
        require(!attribution::map_ipv4_endpoint(invalid.data(), invalid.size(),
                                                actual.data(), actual.size()),
                "invalid source endpoint mapped");
        require(actual == before, "invalid mapping changed output");
    }
    actual.fill(0xa5); const Endpoint before = actual;
    require(!attribution::map_ipv4_endpoint(nullptr, local.size(), actual.data(), actual.size()),
            "null mapping source accepted");
    require(actual == before, "null source mapping changed output");
    require(!attribution::map_ipv4_endpoint(local.data(), local.size(), nullptr, actual.size()),
            "null mapping output accepted");

    Bytes exact = table({tcp6(mapped_local, mapped_remote, 401)});
    expect_result(mapped_result(exact, local, remote), attribution::owner_found, 401,
                  "IPv4 flow did not find exact mapped IPv6 owner");
    expect_result(mapped_result(table({}), local, remote), attribution::owner_none, 0,
                  "empty mapped IPv6 table did not yield NONE");
    expect_result(mapped_result(table({tcp6(mapped_local, mapped_remote, 401),
                                        tcp6(mapped_local, mapped_remote, 402)}), local, remote),
                  attribution::owner_ambiguous, 0, "mapped IPv6 owner conflict was accepted");
    expect_result(mapped_result(table({tcp6(mapped_local, mapped_remote, 0),
                                        tcp6(mapped_local, mapped_remote, 401)}), local, remote),
                  attribution::owner_found, 401, "mapped PID0 row hid valid owner");
    for (bool change_local : {false, true}) {
        Endpoint a = mapped_local, b = mapped_remote;
        (change_local ? a : b)[24] = 1;
        expect_result(mapped_result(table({tcp6(a, b, 401)}), local, remote),
                      attribution::owner_none, 0, "mapped lookup ignored IPv6 scope");
        a = mapped_local; b = mapped_remote;
        (change_local ? a : b)[23] ^= 1;
        expect_result(mapped_result(table({tcp6(a, b, 401)}), local, remote),
                      attribution::owner_none, 0, "mapped lookup ignored endpoint address");
        a = mapped_local; b = mapped_remote;
        (change_local ? a : b)[3] ^= 1;
        expect_result(mapped_result(table({tcp6(a, b, 401)}), local, remote),
                      attribution::owner_none, 0, "mapped lookup ignored endpoint port");
        a = mapped_local; b = mapped_remote;
        (change_local ? a : b)[18] = 0;
        expect_result(mapped_result(table({tcp6(a, b, 401)}), local, remote),
                      attribution::owner_none, 0, "mapped lookup accepted only one mapped endpoint");
    }
    expect_result(mapped_result(exact, local, mapped_remote), attribution::owner_invalid, 0,
                  "mixed IPv4/IPv6 remote accepted by mapping lookup");
    expect_result(mapped_result(exact, mapped_local, remote), attribution::owner_invalid, 0,
                  "mixed IPv4/IPv6 local accepted by mapping lookup");
    expect_result(mapped_result(exact, mapped_local, mapped_remote), attribution::owner_invalid, 0,
                  "native IPv6 endpoints accepted by IPv4 mapping lookup");
    expect_result(attribution::lookup_tcp_mapped_owner(exact.data(), exact.size(),
                     exact.size() - 1, local.data(), local.size(), remote.data(), remote.size()),
                  attribution::owner_invalid, 0, "mapped lookup ignored table truncation");
    expect_result(attribution::lookup_tcp_mapped_owner(exact.data(), exact.size(), exact.size(),
                     local.data(), 15, remote.data(), remote.size()),
                  attribution::owner_invalid, 0, "mapped lookup accepted short local endpoint");
    expect_result(attribution::lookup_tcp_mapped_owner(exact.data(), exact.size(), exact.size(),
                     local.data(), local.size(), remote.data(), 15),
                  attribution::owner_invalid, 0, "mapped lookup accepted short remote endpoint");
}

static void combination_tests()
{
    const attribution::owner_status statuses[] = {attribution::owner_found,
        attribution::owner_none, attribution::owner_invalid, attribution::owner_ambiguous,
        attribution::owner_unavailable};
    for (attribution::owner_status first : statuses) {
        for (attribution::owner_status second : statuses) {
            const attribution::owner_result a = {first, first == attribution::owner_found ? 501u : 0u};
            const attribution::owner_result b = {second, second == attribution::owner_found ? 501u : 0u};
            attribution::owner_status expected;
            if (first == attribution::owner_invalid || second == attribution::owner_invalid)
                expected = attribution::owner_invalid;
            else if (first == attribution::owner_ambiguous || second == attribution::owner_ambiguous)
                expected = attribution::owner_ambiguous;
            else if (first == attribution::owner_found || second == attribution::owner_found)
                expected = attribution::owner_found;
            else if (first == attribution::owner_unavailable || second == attribution::owner_unavailable)
                expected = attribution::owner_unavailable;
            else expected = attribution::owner_none;
            expect_result(attribution::combine_tcp_owners(a, b), expected,
                          expected == attribution::owner_found ? 501 : 0,
                          "TCP result combination status precedence incorrect");
        }
    }
    const attribution::owner_result a = {attribution::owner_found, 501};
    const attribution::owner_result b = {attribution::owner_found, 502};
    expect_result(attribution::combine_tcp_owners(a, b), attribution::owner_ambiguous, 0,
                  "different AF4/AF6 owners did not yield AMBIGUOUS");
    expect_result(attribution::combine_tcp_owners(b, a), attribution::owner_ambiguous, 0,
                  "AF4/AF6 owner conflict depended on query order");
    for (attribution::owner_status status : statuses) {
        const attribution::owner_result broken = {status, status == attribution::owner_found ? 0u : 501u};
        expect_result(attribution::combine_tcp_owners(broken, a), attribution::owner_invalid, 0,
                      "invalid first owner-result invariant accepted");
        expect_result(attribution::combine_tcp_owners(a, broken), attribution::owner_invalid, 0,
                      "invalid second owner-result invariant accepted");
    }
    const attribution::owner_result unknown = {static_cast<attribution::owner_status>(999), 0};
    expect_result(attribution::combine_tcp_owners(unknown, a), attribution::owner_invalid, 0,
                  "unknown first owner status accepted");
    expect_result(attribution::combine_tcp_owners(a, unknown), attribution::owner_invalid, 0,
                  "unknown second owner status accepted");
}


static void udp_result_tests(unsigned int family)
{
    Endpoint local = family == 2 ? endpoint4(10, 50000) : endpoint6(10, 50000, 7);
    Endpoint wildcard = local;
    std::memset(wildcard.data() + (family == 2 ? 4 : 8), 0, family == 2 ? 4 : 16);
    auto row = [family](const Endpoint &a, unsigned int pid) {
        return family == 2 ? udp4(a, pid) : udp6(a, pid);
    };
    auto lookup = [family, local](const Bytes &bytes) {
        return attribution::lookup_udp_owner(bytes.data(), bytes.size(), bytes.size(),
                                              family, local.data(), local.size());
    };
    expect_result(lookup(table({row(local, 701)})), attribution::owner_found, 701,
                  "UDP exact result lost FOUND status");
    expect_result(lookup(table({})), attribution::owner_none, 0,
                  "UDP empty result did not preserve NONE status");
    expect_result(lookup(table({row(local, 0)})), attribution::owner_invalid, 0,
                  "UDP PID0 became absence and allowed fallback");
    for (bool reverse : {false, true}) {
        Bytes unknown = reverse ? table({row(local, 701), row(local, 0)}) :
                                  table({row(local, 0), row(local, 701)});
        expect_result(lookup(unknown), attribution::owner_invalid, 0,
                      "UDP unknown matching owner was hidden by known row");
        Bytes clash = reverse ? table({row(local, 701), row(wildcard, 702)}) :
                                table({row(wildcard, 702), row(local, 701)});
        expect_result(lookup(clash), attribution::owner_ambiguous, 0,
                      "UDP compatible owners were not reported ambiguous");
    }
    Bytes broken(3, 0);
    expect_result(lookup(broken), attribution::owner_invalid, 0,
                  "UDP truncated count did not preserve INVALID status");
    Bytes valid = table({row(local, 701)});
    expect_result(attribution::lookup_udp_owner(valid.data(), valid.size() - 1,
                      valid.size(), family, local.data(), local.size()),
                  attribution::owner_invalid, 0, "UDP oversized returned size accepted");
    Endpoint other = local; other[3] ^= 1;
    expect_result(lookup(table({row(other, 0), row(local, 701)})),
                  attribution::owner_found, 701, "unrelated UDP PID0 row hid exact owner");
    Bytes upper_bits = valid;
    const unsigned int port_offset = family == 2 ? 4 : 20;
    upper_bits[4 + port_offset + 2] = upper_bits[4 + port_offset + 3] = 0xff;
    expect_result(lookup(upper_bits), attribution::owner_found, 701,
                  "unused UDP MIB port DWORD bits changed owner");
}

static void udp_mapped_tests()
{
    Endpoint local = endpoint4(10, 50000), mapped = {{0}};
    require(attribution::map_ipv4_endpoint(local.data(), local.size(), mapped.data(), mapped.size()),
            "UDP fixture IPv4 mapping failed");
    auto lookup = [local](const Bytes &bytes) {
        return attribution::lookup_udp_mapped_owner(bytes.data(), bytes.size(), bytes.size(),
                                                     local.data(), local.size());
    };
    expect_result(lookup(table({udp6(mapped, 801)})), attribution::owner_found, 801,
                  "UDP explicit IPv4-mapped owner not found");
    expect_result(lookup(table({})), attribution::owner_none, 0,
                  "empty mapped UDP table did not yield NONE");
    Endpoint any = mapped; std::memset(any.data() + 8, 0, 16);
    expect_result(lookup(table({udp6(any, 801)})), attribution::owner_ambiguous, 0,
                  "UDP6 ANY incorrectly proved ownership of an IPv4 packet");
    expect_result(lookup(table({udp6(mapped, 801), udp6(any, 801)})),
                  attribution::owner_ambiguous, 0, "UDP6 ANY uncertainty was concealed by exact owner");
    mapped[24] = 1;
    expect_result(lookup(table({udp6(mapped, 801)})), attribution::owner_none, 0,
                  "mapped UDP owner ignored IPv6 scope");
    Bytes bytes = table({});
    expect_result(attribution::lookup_udp_mapped_owner(bytes.data(), bytes.size(), bytes.size(),
                      any.data(), any.size()), attribution::owner_invalid, 0,
                  "UDP mapped lookup accepted a native IPv6 source");
}

static void udp_frame_tests()
{
    namespace validation = exl_udp_validation;
    for (unsigned int family : {2u, 23u}) {
        Endpoint local = family == 2 ? endpoint4(10, 50000) : endpoint6(10, 50000, 7);
        Endpoint remote = family == 2 ? endpoint4(80, 443) : endpoint6(80, 443, 8);
        exl_udp_lifecycle_req lifecycle = {};
        lifecycle.tag = 1; lifecycle.endpoint_id = 2; lifecycle.process_id = 3;
        lifecycle.ip_family = static_cast<unsigned short>(family);
        std::memcpy(lifecycle.local_address, local.data(), local.size());
        require(validation::valid_lifecycle(lifecycle), "valid UDP lifecycle rejected");
        exl_udp_lifecycle_req invalid_lifecycle = lifecycle;
        invalid_lifecycle.tag = 0;
        require(!validation::valid_lifecycle(invalid_lifecycle), "UDP lifecycle tag0 accepted");
        invalid_lifecycle = lifecycle; invalid_lifecycle.endpoint_id = 0;
        require(!validation::valid_lifecycle(invalid_lifecycle), "UDP lifecycle endpoint0 accepted");
        invalid_lifecycle = lifecycle; invalid_lifecycle.process_id = 0;
        require(!validation::valid_lifecycle(invalid_lifecycle), "UDP lifecycle PID0 accepted");
        invalid_lifecycle = lifecycle; invalid_lifecycle.ip_family = 0;
        require(!validation::valid_lifecycle(invalid_lifecycle), "UDP lifecycle invalid family accepted");
        invalid_lifecycle = lifecycle; invalid_lifecycle.local_address[1] = 1;
        require(!validation::valid_lifecycle(invalid_lifecycle), "UDP lifecycle conflicting family accepted");
        invalid_lifecycle = lifecycle;
        invalid_lifecycle.local_address[2] = invalid_lifecycle.local_address[3] = 0;
        require(!validation::valid_lifecycle(invalid_lifecycle), "UDP lifecycle port0 accepted");

        exl_udp_connect_req connect = {};
        connect.tag = lifecycle.tag; connect.endpoint_id = lifecycle.endpoint_id;
        connect.process_id = lifecycle.process_id; connect.ip_family = lifecycle.ip_family;
        std::memcpy(connect.local_address, local.data(), local.size());
        std::memcpy(connect.remote_address, remote.data(), remote.size());
        require(validation::valid_connect(connect), "valid UDP connect request rejected");
        exl_udp_connect_req invalid_connect = connect;
        invalid_connect.remote_address[0] = family == 2 ? 23 : 2;
        require(!validation::valid_connect(invalid_connect), "cross-family UDP connect accepted");
        invalid_connect = connect;
        invalid_connect.remote_address[2] = invalid_connect.remote_address[3] = 0;
        require(!validation::valid_connect(invalid_connect), "UDP connect remote port0 accepted");

        exl_udp_datagram_req request = {};
        request.tag = lifecycle.tag; request.endpoint_id = lifecycle.endpoint_id;
        request.process_id = lifecycle.process_id; request.ip_family = lifecycle.ip_family;
        request.direction = EXL_DIR_OUT;
        std::memcpy(request.local_address, local.data(), local.size());
        std::memcpy(request.remote_address, remote.data(), remote.size());
        for (unsigned int options : {0u, 1u, 4096u}) {
            for (unsigned int length : {0u, 1u, 65535u}) {
                request.options_length = options; request.payload_length = length;
                const unsigned int frame = static_cast<unsigned int>(sizeof(request)) + options + length;
                for (unsigned int direction : {EXL_DIR_IN, EXL_DIR_OUT}) {
                    request.direction = static_cast<unsigned char>(direction);
                    require(validation::valid_datagram(request, frame), "valid exact UDP frame rejected");
                    require(!validation::valid_datagram(request, frame + 1), "UDP frame trailing byte accepted");
                    require(!validation::valid_datagram(request, frame - 1), "UDP frame missing byte accepted");
                }
            }
        }
        request.options_length = 0; request.payload_length = 0;
        const unsigned int empty_frame = static_cast<unsigned int>(sizeof(request));
        for (unsigned int direction : {0u, 3u, 255u}) {
            request.direction = static_cast<unsigned char>(direction);
            require(!validation::valid_datagram(request, empty_frame), "invalid UDP direction accepted");
        }
        request.direction = EXL_DIR_OUT; request.reserved = 1;
        require(!validation::valid_datagram(request, empty_frame), "UDP reserved byte accepted");
        request.reserved = 0; request.options_length = 4097;
        require(!validation::valid_datagram(request, empty_frame + 4097), "oversized UDP options accepted");
        request.options_length = 0; request.payload_length = 65536;
        require(!validation::valid_datagram(request, empty_frame + 65536), "oversized UDP payload accepted");
        request.payload_length = 0xffffffffu; request.options_length = 0xffffffffu;
        require(!validation::valid_datagram(request, empty_frame), "wrapped UDP frame lengths accepted");
        request.payload_length = request.options_length = 0;
        require(!validation::valid_datagram(request, 0), "short fixed UDP frame accepted");
        require(!validation::valid_datagram(request, EXL_MAX_PAYLOAD + 1), "oversized fixed UDP frame accepted");
        request.remote_address[1] = 1;
        require(!validation::valid_datagram(request, empty_frame), "UDP datagram mixed family accepted");

        require(validation::valid_post_arguments(remote.data(), nullptr, 0, 0),
                "zero-length NULL-buffer UDP post rejected");
        require(validation::valid_post_arguments(remote.data(), "x", 65535, 4096),
                "valid UDP post argument bounds rejected");
        require(!validation::valid_post_arguments(remote.data(), nullptr, 1, 0),
                "positive-length NULL-buffer UDP post accepted");
        require(!validation::valid_post_arguments(remote.data(), "x", -1, 0),
                "negative UDP payload length accepted");
        require(!validation::valid_post_arguments(remote.data(), "x", 65536, 0),
                "oversized UDP post payload accepted");
        require(!validation::valid_post_arguments(remote.data(), "x", 1, -1),
                "negative UDP options were coerced to empty options");
        require(!validation::valid_post_arguments(remote.data(), "x", 1, 4097),
                "oversized UDP options accepted");
        require(!validation::valid_post_arguments(nullptr, "x", 1, 0),
                "NULL UDP remote accepted");
        Endpoint invalid_remote = remote; invalid_remote[2] = invalid_remote[3] = 0;
        require(!validation::valid_post_arguments(invalid_remote.data(), "x", 1, 0),
                "UDP post remote port0 accepted");
    }
    require(validation::context_matches(11, 12, 13, 13, 12), "active UDP context rejected");
    require(!validation::context_matches(0, 12, 13, 13, 12), "UDP context tag0 accepted");
    require(!validation::context_matches(11, 0, 13, 13, 0), "UDP context endpoint0 accepted");
    require(!validation::context_matches(11, 12, 0, 0, 12), "UDP context session0 accepted");
    require(!validation::context_matches(11, 12, 13, 14, 12), "stale UDP session context accepted");
    require(!validation::context_matches(11, 12, 13, 13, 14), "UDP post stole another endpoint context");
    require(!validation::context_matches(11, 12, 13, 13, 0), "UDP post endpoint0 accepted");
}

int main()
{
    {
        Endpoint source = endpoint4(40, 9000), output;
        std::memset(source.data() + 8, 0xa5, 20);
        output.fill(0xcc);
        require(exl_udp_validation::canonical_post_remote(source.data(), 8, output.data(), output.size()),
                "defined IPv4 sockaddr fields were not sufficient");
        require(!std::memcmp(output.data(), source.data(), 8), "IPv4 routing fields changed");
        require(attribution::zero_bytes(output.data() + 8, 20), "IPv4 caller padding leaked into IPC");
        require(exl_udp_validation::canonical_post_remote(source.data(), source.size(), source.data(), source.size()),
                "aliased canonical address copy failed");
        require(attribution::zero_bytes(source.data() + 8, 20), "aliased padding was not zeroed");
        for (size_t readable = 0; readable < 8; ++readable) {
            output.fill(0xcc); const Endpoint before = output;
            require(!exl_udp_validation::canonical_post_remote(source.data(), readable, output.data(), output.size()),
                    "short IPv4 post remote accepted");
            require(output == before, "short post remote changed output");
        }
        source = endpoint6(40, 9000, 7);
        require(exl_udp_validation::canonical_post_remote(source.data(), source.size(), output.data(), output.size()),
                "complete IPv6 post remote rejected");
        require(output == source, "IPv6 scope or flow metadata was silently changed");
        const Endpoint before = output;
        require(!exl_udp_validation::canonical_post_remote(source.data(), 27, output.data(), output.size()),
                "short IPv6 post remote accepted");
        require(output == before, "short IPv6 post remote changed output");
        require(!exl_udp_validation::canonical_post_remote(source.data(), source.size(), output.data(), 27),
                "short output post remote accepted");
        require(!exl_udp_validation::canonical_post_remote(nullptr, 28, output.data(), output.size()),
                "null post remote accepted");
    }
    tcp_tuple_tests(2);
    tcp_tuple_tests(23);
    udp_bounds_and_ownership(2);
    udp_bounds_and_ownership(23);
    tcp_result_tests(2);
    tcp_result_tests(23);
    mapped_endpoint_tests();
    combination_tests();
    udp_result_tests(2);
    udp_result_tests(23);
    udp_mapped_tests();
    udp_frame_tests();
    std::printf("PASS: shim socket attribution (%u assertions)\n", checks);
}
