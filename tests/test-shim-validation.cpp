// Cloud-safe tests for the exact freestanding helpers used by nfapi.dll.
#include "../shim/nfapi/ipc_validation.h"
#include "../shim/nfapi/tcp_callback_policy.h"

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

static unsigned int checks;

static void require(bool condition, const char *message)
{
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

static void valid_endpoint(const wchar_t *text, unsigned int a, unsigned int b,
                           unsigned int c, unsigned int d, unsigned int port)
{
    unsigned char guarded[18];
    std::memset(guarded, 0xa5, sizeof(guarded));
    require(exl_ipc_validation::parse_loopback_endpoint(text, guarded + 1),
            "valid loopback endpoint rejected");
    unsigned char expected[16] = {2, 0, (unsigned char)(port >> 8), (unsigned char)port,
                                 (unsigned char)a, (unsigned char)b,
                                 (unsigned char)c, (unsigned char)d};
    require(std::memcmp(guarded + 1, expected, sizeof(expected)) == 0,
            "wrong Windows sockaddr address/port/zero padding");
    require(guarded[0] == 0xa5 && guarded[17] == 0xa5, "endpoint output canary changed");
}

static void endpoint_tests()
{
    valid_endpoint(L"127.0.0.1", 127, 0, 0, 1, EXL_DEFAULT_PORT);
    valid_endpoint(L"127.0.0.1:51900", 127, 0, 0, 1, 51900);
    valid_endpoint(L"127.0.0.0:1", 127, 0, 0, 0, 1);
    valid_endpoint(L"127.255.255.255:65535", 127, 255, 255, 255, 65535);
    valid_endpoint(L"127.12.34.56:80", 127, 12, 34, 56, 80);
    // Numeric fields are decimal even with leading zeros; no OS string parser
    // gets to reinterpret them as octal or a different address notation.
    valid_endpoint(L"00127.000.000.001:00001", 127, 0, 0, 1, 1);

    const wchar_t *invalid[] = {
        nullptr, L"", L"127.0.0", L"127.0.0.1.", L"127.0.0.1.2",
        L"127..0.1:51900", L"127.0..1", L".127.0.0.1", L"127.0.0.",
        L"127.0.0.256:51900", L"127.0.0.999:51900", L"256.0.0.1",
        L"4294967423.0.0.1:51900", L"127.0.4294967296.1",
        L"999999999999999999999999999999999999999999.0.0.1",
        L"127.0.0.1:", L"127.0.0.1:0", L"127.0.0.1:65536",
        L"127.0.0.1:4295019196", L"127.0.0.1:9999999999999999999999999999",
        L"127.0.0.1:51900garbage", L"127.0.0.1:1:2", L"127.0.0.1:0x1234",
        L"127.0.0.1:-1", L"127.0.0.1:+1", L"127.0.0.1: 1",
        L" 127.0.0.1", L"127.0.0.1 ", L"127.0.0.1:51900\n",
        L"127.0.0.1\n:51900", L"127.0.0.1:\uFF11", L"\uFF11\uFF12\uFF17.0.0.1",
        L"126.255.255.255", L"128.0.0.1", L"0.0.0.0", L"192.0.2.1:51900",
        L"255.255.255.255", L"localhost:51900", L"2130706433:51900",
        L"0x7f.0.0.1", L"[::1]:51900", L"::1", L"127/8:51900"
    };
    for (const wchar_t *text : invalid) {
        unsigned char address[16];
        std::memset(address, 0xa5, sizeof(address));
        require(!exl_ipc_validation::parse_loopback_endpoint(text, address),
                "malformed/non-loopback endpoint accepted");
        for (unsigned char byte : address)
            require(byte == 0xa5, "invalid endpoint changed output");
    }
    require(!exl_ipc_validation::parse_loopback_endpoint(L"127.0.0.1", nullptr),
            "null endpoint output accepted");

    // Deterministic generated valid endpoints exercise every octet boundary
    // and many ports independently of the decimal parser's implementation.
    for (unsigned int i = 0; i < 1024; ++i) {
        wchar_t text[64];
        unsigned int b = i & 255, c = (i * 17) & 255, d = (i * 97) & 255;
        unsigned int port = (i * 61) % 65535 + 1;
        std::swprintf(text, sizeof(text) / sizeof(text[0]), L"127.%u.%u.%u:%u", b, c, d, port);
        valid_endpoint(text, 127, b, c, d, port);
    }
}

static void frame_tests()
{
    exl_header header = {EXL_MAGIC, EXL_MSG_UDP_DATAGRAM_REQ, 0, 0};
    require(exl_ipc_validation::valid_frame_header(header), "empty frame rejected");
    // Both the largest ordinary UDP payload and its framing/options must fit;
    // the old 64 KiB shim receive cap rejected this valid protocol range.
    header.length = (unsigned int)sizeof(exl_udp_datagram_req) + 65507 + 4096;
    require(exl_ipc_validation::valid_frame_header(header), "large UDP frame rejected");
    header.length = EXL_MAX_PAYLOAD;
    require(exl_ipc_validation::valid_frame_header(header), "maximum frame rejected");
    header.length = EXL_MAX_PAYLOAD + 1;
    require(!exl_ipc_validation::valid_frame_header(header), "oversized frame accepted");
    header.length = UINT_MAX;
    require(!exl_ipc_validation::valid_frame_header(header), "overflowed length accepted");
    header.length = 16;
    for (unsigned int bit = 0; bit < 16; ++bit) {
        header.flags = (unsigned short)(1u << bit);
        require(!exl_ipc_validation::valid_frame_header(header), "reserved flag accepted");
    }
    header.flags = 0;
    for (unsigned int bit = 0; bit < 32; ++bit) {
        header.magic = EXL_MAGIC ^ (1u << bit);
        require(!exl_ipc_validation::valid_frame_header(header), "bad frame magic accepted");
    }
}

static void pid_reply_tests()
{
    const std::string path = "Z:\\games\\Game.exe";
    exl_resolve_pid_reply reply = {17, (unsigned int)path.size(), 0};
    std::vector<char> frame(sizeof(reply) + path.size());
    std::memcpy(frame.data(), &reply, sizeof(reply));
    std::memcpy(frame.data() + sizeof(reply), path.data(), path.size());
    wchar_t guarded[128];
    for (wchar_t &value : guarded) value = 0x1234;
    require(exl_ipc_validation::copy_pid_reply_path(reply, frame.data(),
            (unsigned int)frame.size(), guarded + 1, 126), "valid PID reply rejected");
    for (unsigned int i = 0; i < path.size(); ++i)
        require(guarded[1 + i] == (wchar_t)(unsigned char)path[i], "PID path mismatch");
    require(guarded[path.size() + 1] == 0, "PID path lacks terminator");
    require(guarded[0] == 0x1234 && guarded[127] == 0x1234, "PID output canary changed");

    // Keep existing caller-buffer truncation behavior, including a one-character
    // output, while proving that the byte after the capacity is untouched.
    for (unsigned long capacity = 1; capacity <= path.size() + 2; ++capacity) {
        for (wchar_t &value : guarded) value = 0x1234;
        require(exl_ipc_validation::copy_pid_reply_path(reply, frame.data(),
                (unsigned int)frame.size(), guarded + 1, capacity), "bounded PID copy rejected");
        unsigned long count = path.size() < capacity ? path.size() : capacity - 1;
        require(guarded[count + 1] == 0, "bounded copy lacks terminator");
        require(guarded[0] == 0x1234 && guarded[capacity + 1] == 0x1234,
                "bounded PID copy wrote outside capacity");
    }

    struct invalid_case {
        unsigned int frame_length, path_length, reserved;
        unsigned long capacity;
    };
    const invalid_case invalid[] = {
        {0, 1, 0, 126}, {15, 1, 0, 126}, {16, 1, 0, 126},
        {16, 0, 0, 126}, {17, 2, 0, 126}, {17, UINT_MAX, 0, 126},
        {18, 1, 0, 126}, {17, 1, 1, 126}, {17, 1, UINT_MAX, 126},
        {17, 1, 0, 0}, {EXL_MAX_PAYLOAD + 1, 1, 0, 126},
        {UINT_MAX, UINT_MAX - 16, 0, 126}
    };
    for (const invalid_case &test : invalid) {
        reply.path_length = test.path_length;
        reply.reserved = test.reserved;
        for (wchar_t &value : guarded) value = 0x1234;
        require(!exl_ipc_validation::copy_pid_reply_path(reply, frame.data(),
                test.frame_length, guarded + 1, test.capacity), "malformed PID reply accepted");
        for (wchar_t value : guarded)
            require(value == 0x1234, "malformed PID reply changed output");
    }

    reply.path_length = (unsigned int)path.size(); reply.reserved = 0;
    require(!exl_ipc_validation::copy_pid_reply_path(reply, nullptr,
            (unsigned int)frame.size(), guarded, 128), "null PID frame accepted");
    require(!exl_ipc_validation::copy_pid_reply_path(reply, frame.data(),
            (unsigned int)frame.size(), nullptr, 128), "null PID output accepted");

    // Boundary frame consumes the entire shared protocol allowance. A sanitizer
    // catches an off-by-one read/write here, independently of Wine or sockets.
    frame.assign(EXL_MAX_PAYLOAD, 'x');
    reply.path_length = EXL_MAX_PAYLOAD - (unsigned int)sizeof(reply);
    std::vector<wchar_t> full_path(reply.path_length + 3, (wchar_t)0x1234);
    require(exl_ipc_validation::copy_pid_reply_path(reply, frame.data(),
            (unsigned int)frame.size(), full_path.data() + 1, reply.path_length + 1),
            "maximum-size PID frame rejected");
    require(full_path[1] == L'x' && full_path[reply.path_length] == L'x',
            "maximum-size PID path corrupted");
    require(full_path[0] == 0x1234 && full_path[reply.path_length + 1] == 0 &&
            full_path[reply.path_length + 2] == 0x1234, "maximum PID copy canary changed");
}

static void tcp_callback_policy_tests()
{
    using namespace exl_socket_attribution;
    const owner_status rejected[] = {owner_invalid, owner_ambiguous,
                                    (owner_status)99};
    for (owner_status status : rejected) {
        for (unsigned int fallback : {0u, 123u}) {
            const auto selected = exl_tcp_callback_policy::select_process(result(status), fallback);
            require(!selected.pid && selected.origin == exl_pid_domain::pid_unknown,
                    "invalid/ambiguous Windows ownership allowed a Linux fallback");
        }
    }
    for (owner_status status : {owner_none, owner_unavailable}) {
        auto selected = exl_tcp_callback_policy::select_process(result(status), 123);
        require(selected.pid == 123 && selected.origin == exl_pid_domain::pid_linux,
                "verified nonzero Linux fallback was lost");
        require(!exl_tcp_callback_policy::select_process(result(status), 0).pid,
                "PID zero selected a TCP callback");
        require(!exl_tcp_callback_policy::select_process(result(status, 5), 123).pid,
                "inconsistent no-owner result selected a TCP callback");
    }
    auto selected = exl_tcp_callback_policy::select_process(result(owner_found, 5), 123);
    require(selected.pid == 5 && selected.origin == exl_pid_domain::pid_windows,
            "exact Windows owner was not preferred");
    require(!exl_tcp_callback_policy::select_process(result(owner_found), 123).pid,
            "zero Windows owner was replaced with an unrelated Linux PID");

    exl_pid_domain::registry registry = {};
    require(exl_pid_domain::remember_pid(registry, 123, exl_pid_domain::pid_linux),
            "Linux callback PID registration failed");
    require(!exl_pid_domain::remember_pid(registry, 123, exl_pid_domain::pid_windows),
            "numeric PID collision was accepted for another callback");
    require(exl_pid_domain::lookup_pid(registry, 123) == exl_pid_domain::pid_ambiguous,
            "PID collision lost its fail-closed domain");

    exl_tcp_connect_req request = {};
    request.tag = ULLONG_MAX;
    request.filtering_flag = UINT_MAX;
    for (unsigned int i = 0; i < sizeof(request.remote_address); ++i)
        request.remote_address[i] = (unsigned char)(i + 17);
    exl_tcp_connect_reply reply;
    std::memset(&reply, 0xa5, sizeof(reply));
    exl_tcp_callback_policy::passthrough_reply(request, reply);
    require(reply.tag == request.tag && reply.filtering_flag == request.filtering_flag,
            "skipped callback changed correlation/filtering metadata");
    require(reply.verdict == EXL_VERDICT_NO_HANDLER,
            "skipped callback claimed an executed vendor callback");
    require(!reply.mutated_flag && !reply.mutated_remote &&
            !reply.reserved[0] && !reply.reserved[1], "skipped callback retained mutation flags");
    require(!std::memcmp(reply.remote_address, request.remote_address, 28),
            "skipped callback fabricated a redirect destination");
}

int main()
{
    endpoint_tests();
    frame_tests();
    pid_reply_tests();
    tcp_callback_policy_tests();
    std::printf("PASS: %u shim IPC validation checks (synthetic; no Wine or ExitLag)\n", checks);
    return 0;
}
