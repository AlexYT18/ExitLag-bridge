#define _POSIX_C_SOURCE 200809L
#include "../backend/tcp_attribution.h"

#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static char temporary_dir[] = "/tmp/exl-tcp-attribution-XXXXXX";
static char tcp_path[128], tcp6_path[128];
static const char header[] =
    "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
static const char *const normal_parts[] = {
    "0:", "0302017F:9C40", "096433C6:01BB", "02", "00000000:00000000",
    "00:00000000", "00000000", "1000", "0", "12345"
};
static unsigned char local4[4], remote4[4], local6[16], remote6[16];

static void cleanup(void)
{
    unlink(tcp_path);
    unlink(tcp6_path);
    rmdir(temporary_dir);
}

static FILE *table(const char *path)
{
    FILE *file = fopen(path, "w");
    assert(file);
    assert(fputs(header, file) >= 0);
    return file;
}

static void empty_tables(void)
{
    assert(fclose(table(tcp_path)) == 0);
    assert(fclose(table(tcp6_path)) == 0);
}

static void row(FILE *file, const char *local, const char *remote,
                const char *state, unsigned long inode)
{
    assert(fprintf(file, " 0: %s %s %s 00000000:00000000 00:00000000 00000000 1000 0 %lu 1 0000000000000000 20 4 30 10 -1\n",
                   local, remote, state, inode) > 0);
}

static void expect_tuple(enum tcp_attribution_result expected, unsigned long wanted,
                         int family, const unsigned char *local, unsigned short local_port,
                         const unsigned char *remote, unsigned short remote_port)
{
    unsigned long inode = 777;
    enum tcp_attribution_result result = tcp_attribution_lookup_files(tcp_path, tcp6_path,
        family, local, local_port, remote, remote_port, &inode);
    assert(result == expected);
    assert(inode == wanted);
}

static void expect(enum tcp_attribution_result expected, unsigned long inode)
{
    expect_tuple(expected, inode, AF_INET, local4, 40000, remote4, 443);
}

static void ipv4_tuple_and_conflicts(void)
{
    empty_tables();
    expect(TCP_ATTR_NONE, 0);
    FILE *file = table(tcp_path);
    /* Same local endpoint and misleading partial matches precede the owner. */
    row(file, "0302017F:9C40", "0A6433C6:01BB", "01", 111);
    row(file, "0302017F:9C40", "096433C6:01BC", "01", 222);
    row(file, "0402017F:9C40", "096433C6:01BB", "01", 333);
    row(file, "0302017F:9C41", "096433C6:01BB", "01", 444);
    row(file, "0302017F:9C40", "096433C6:01BB", "0A", 555);
    row(file, "0302017F:9C40", "096433C6:01BB", "06", 666);
    row(file, "0302017F:9C40", "096433C6:01BB", "01", 0);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_NONE, 0);
    file = fopen(tcp_path, "a"); assert(file);
    row(file, "0302017F:9C40", "096433C6:01BB", "02", 12345);
    /* Repeated sightings of the SAME socket are not conflicting identities. */
    row(file, "0302017F:9C40", "096433C6:01BB", "01", 12345);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_FOUND, 12345);
    for (int reverse = 0; reverse < 2; ++reverse) {
        file = table(tcp_path);
        row(file, "0302017F:9C40", "096433C6:01BB", "02", reverse ? 7 : 8);
        row(file, "0302017F:9C40", "096433C6:01BB", "02", reverse ? 8 : 7);
        assert(fclose(file) == 0);
        expect(TCP_ATTR_AMBIGUOUS, 0);
    }
}

static void ipv6_and_mapped(void)
{
    empty_tables();
    FILE *file = table(tcp6_path);
    row(file, "B80D012078563412F0DEBC9A78563412:9C40",
        "B80D012000CD00AB020100EF06050403:01BC", "01", 111);
    row(file, "B80D012078563412F0DEBC9A78563412:9C40",
        "B80D012000CD00AB020100EF06050403:01BB", "01", 23456);
    assert(fclose(file) == 0);
    expect_tuple(TCP_ATTR_FOUND, 23456, AF_INET6, local6, 40000, remote6, 443);
    expect(TCP_ATTR_NONE, 0);
    file = fopen(tcp6_path, "a"); assert(file);
    row(file, "B80D012078563412F0DEBC9A78563412:9C40",
        "B80D012000CD00AB020100EF06050403:01BB", "01", 23457);
    assert(fclose(file) == 0);
    expect_tuple(TCP_ATTR_AMBIGUOUS, 0, AF_INET6, local6, 40000, remote6, 443);
    file = table(tcp6_path);
    /* Mapping only the local endpoint must never find this remote. */
    row(file, "0000000000000000FFFF00000302017F:9C40",
        "000000000000000000000000096433C6:01BB", "01", 111);
    row(file, "0000000000000000FFFF00000302017F:9C40",
        "0000000000000000FFFF00000A6433C6:01BB", "01", 222);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_NONE, 0);
    file = fopen(tcp6_path, "a"); assert(file);
    row(file, "0000000000000000FFFF00000302017F:9C40",
        "0000000000000000FFFF0000096433C6:01BB", "02", 34567);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_FOUND, 34567);
    file = table(tcp_path);
    row(file, "0302017F:9C40", "096433C6:01BB", "02", 34567);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_FOUND, 34567);
    file = table(tcp_path);
    row(file, "0302017F:9C40", "096433C6:01BB", "02", 45678);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_AMBIGUOUS, 0);
    unsigned char zero[16] = { 0 };
    expect_tuple(TCP_ATTR_NONE, 0, AF_INET6, zero, 40000, zero, 443);
    file = fopen(tcp6_path, "a"); assert(file);
    row(file, "0000000000000000FFFF00000302017F:9C40",
        "0000000000000000FFFF0000096433C6:01BB", "02", 56789);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_AMBIGUOUS, 0);
    assert(fclose(table(tcp6_path)) == 0);
    unsigned char mapped_local[16], mapped_remote[16];
    assert(inet_pton(AF_INET6, "::ffff:127.1.2.3", mapped_local) == 1);
    assert(inet_pton(AF_INET6, "::ffff:198.51.100.9", mapped_remote) == 1);
    /* An AF_INET6 query must not search tcp, even for a mapped address. */
    expect_tuple(TCP_ATTR_NONE, 0, AF_INET6, mapped_local, 40000, mapped_remote, 443);
}

static void ipv6_scope_and_malformed(void)
{
    empty_tables();
    unsigned char link_local[16];
    assert(inet_pton(AF_INET6, "fe80::1234", link_local) == 1);
    FILE *file = table(tcp6_path);
    row(file, "000080FE000000000000000034120000:9C40",
        "B80D012000CD00AB020100EF06050403:01BB", "01", 23456);
    assert(fclose(file) == 0);
    expect_tuple(TCP_ATTR_INVALID, 0, AF_INET6, link_local, 40000, remote6, 443);
    file = table(tcp6_path);
    row(file, "B80D012078563412F0DEBC9A78563412:9C40",
        "000080FE000000000000000034120000:01BB", "01", 23456);
    assert(fclose(file) == 0);
    expect_tuple(TCP_ATTR_INVALID, 0, AF_INET6, local6, 40000, link_local, 443);
    static const char *const bad_endpoints[] = {
        "B80D012000CD00AB020100EF0605040:01BB",
        "0B80D012000CD00AB020100EF06050403:01BB",
        "B80D012000CD00AB020100EF0605040G:01BB",
        "B80D012000CD00AB020100EF06050403:001BB"
    };
    for (size_t i = 0; i < sizeof(bad_endpoints) / sizeof(bad_endpoints[0]); ++i) {
        file = table(tcp6_path);
        row(file, "B80D012078563412F0DEBC9A78563412:9C40", bad_endpoints[i], "01", 23456);
        assert(fclose(file) == 0);
        expect_tuple(TCP_ATTR_INVALID, 0, AF_INET6, local6, 40000, remote6, 443);
    }
}

static void boundaries_and_bad_arguments(void)
{
    empty_tables();
    FILE *file = table(tcp_path);
    row(file, "0302017f:0000", "096433c6:ffff", "02", ULONG_MAX);
    assert(fclose(file) == 0);
    expect_tuple(TCP_ATTR_FOUND, ULONG_MAX, AF_INET, local4, 0, remote4, 65535);
    unsigned long inode = 999;
    assert(tcp_attribution_lookup_files(tcp_path, tcp6_path, AF_UNIX, local4, 1,
                                        remote4, 1, &inode) == TCP_ATTR_INVALID && inode == 0);
    inode = 999;
    assert(tcp_attribution_lookup_files(NULL, tcp6_path, AF_INET, local4, 1,
                                        remote4, 1, &inode) == TCP_ATTR_INVALID && inode == 0);
    inode = 999;
    assert(tcp_attribution_lookup_files(tcp_path, NULL, AF_INET, local4, 1,
                                        remote4, 1, &inode) == TCP_ATTR_INVALID && inode == 0);
    inode = 999;
    assert(tcp_attribution_lookup_files(tcp_path, tcp6_path, AF_INET, NULL, 1,
                                        remote4, 1, &inode) == TCP_ATTR_INVALID && inode == 0);
    assert(tcp_attribution_lookup_files(tcp_path, tcp6_path, AF_INET, local4, 1,
                                        remote4, 1, NULL) == TCP_ATTR_INVALID);
}

static void malformed_tables(void)
{
    static const struct { size_t field; const char *value; } malformed[] = {
        {0, "-1:"}, {0, "+1:"}, {0, "1:x"}, {0, "4294967296:"},
        {1, "302017F:9C40"}, {1, "00302017F:9C40"}, {1, "0302017G:9C40"},
        {1, "0302017F:9C4"}, {1, "0302017F:19C40"}, {1, "0302017F:+C40"},
        {2, "096433CG:01BB"}, {2, "096433C6:01B"}, {2, "096433C6:001BB"},
        {2, "096433C6:-1BB"}, {3, "2"}, {3, "002"}, {3, "00"}, {3, "FF"},
        {4, "0000000:00000000"}, {4, "00000000:0000000G"},
        {5, "0:00000000"}, {5, "00:000000000"}, {6, "0000000"},
        {7, "+1000"}, {7, "4294967296"}, {8, "-1"}, {9, "12345junk"},
        {9, "+12345"}, {9, "18446744073709551616"}
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        empty_tables();
        FILE *file = table(tcp_path);
        /* A good match cannot hide a later malformed row. */
        row(file, "0302017F:9C40", "096433C6:01BB", "02", 12345);
        for (size_t field = 0; field < 10; ++field)
            assert(fprintf(file, "%s%c", field == malformed[i].field ?
                malformed[i].value : normal_parts[field], field == 9 ? '\n' : ' ') > 0);
        assert(fclose(file) == 0);
        expect(TCP_ATTR_INVALID, 0);
    }
    static const char *const broken_rows[] = {
        "\n", "0: 0302017F:9C40 096433C6:01BB 02\n",
        "0: 0302017F:9C40 096433C6:01BB 02 00000000:00000000 00:00000000 00000000 1000 0 12345"
    };
    for (size_t i = 0; i < sizeof(broken_rows) / sizeof(broken_rows[0]); ++i) {
        empty_tables();
        FILE *file = table(tcp_path);
        assert(fputs(broken_rows[i], file) >= 0);
        assert(fclose(file) == 0);
        expect(TCP_ATTR_INVALID, 0);
    }
    empty_tables();
    FILE *file = table(tcp_path);
    for (size_t i = 0; i < 2048; ++i) assert(fputc('0', file) != EOF);
    assert(fputc('\n', file) != EOF);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_INVALID, 0);
    file = table(tcp_path);
    assert(fwrite("0: \0hidden\n", 1, 11, file) == 11);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_INVALID, 0);
    file = fopen(tcp_path, "w"); assert(file);
    assert(fputs("sl local_address incorrect_header\n", file) >= 0);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_INVALID, 0);
    empty_tables();
    file = table(tcp_path);
    row(file, "0302017F:9C40", "096433C6:01BB", "02", 12345);
    assert(fclose(file) == 0);
    assert(unlink(tcp6_path) == 0);
    expect(TCP_ATTR_INVALID, 0);
    file = table(tcp6_path);
    assert(fputs("malformed ipv6 row\n", file) >= 0);
    assert(fclose(file) == 0);
    expect(TCP_ATTR_INVALID, 0);
    assert(unlink(tcp_path) == 0);
    expect(TCP_ATTR_INVALID, 0);
}

static int socket_reuse(int family)
{
    int fd = socket(family, SOCK_STREAM, 0);
    assert(fd >= 0);
    int one = 1;
    assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
    return fd;
}

static unsigned long socket_inode(int fd)
{
    struct stat metadata;
    assert(fstat(fd, &metadata) == 0);
    return (unsigned long)metadata.st_ino;
}

static void assert_live_tuple(int fd, int family, const unsigned char *local,
    unsigned short local_port, const unsigned char *remote, unsigned short remote_port)
{
    unsigned long inode = 777;
    assert(tcp_attribution_lookup(family, local, local_port, remote, remote_port,
                                  &inode) == TCP_ATTR_FOUND);
    assert(inode == socket_inode(fd));
}

static void live_ipv4(int different_addresses)
{
    int listeners[2], clients[2], accepted[2];
    struct sockaddr_in peers[2], local = { .sin_family = AF_INET };
    assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);
    for (size_t i = 0; i < 2; ++i) {
        listeners[i] = socket_reuse(AF_INET);
        peers[i] = (struct sockaddr_in){ .sin_family = AF_INET };
        assert(inet_pton(AF_INET, different_addresses && i ? "127.0.0.2" : "127.0.0.1",
                         &peers[i].sin_addr) == 1);
        if (different_addresses && i) peers[i].sin_port = peers[0].sin_port;
        assert(bind(listeners[i], (struct sockaddr *)&peers[i], sizeof(peers[i])) == 0);
        socklen_t length = sizeof(peers[i]);
        assert(getsockname(listeners[i], (struct sockaddr *)&peers[i], &length) == 0);
        assert(listen(listeners[i], 1) == 0);
        clients[i] = socket_reuse(AF_INET);
        assert(bind(clients[i], (struct sockaddr *)&local, sizeof(local)) == 0);
        length = sizeof(local);
        assert(getsockname(clients[i], (struct sockaddr *)&local, &length) == 0);
        assert(connect(clients[i], (struct sockaddr *)&peers[i], sizeof(peers[i])) == 0);
        accepted[i] = accept(listeners[i], NULL, NULL);
        assert(accepted[i] >= 0);
    }
    assert(socket_inode(clients[0]) != socket_inode(clients[1]));
    /* Both sockets stay open: selecting the first local port match is wrong
     * for one of them, regardless of /proc enumeration order. */
    for (size_t i = 0; i < 2; ++i) {
        assert_live_tuple(clients[i], AF_INET, (unsigned char *)&local.sin_addr,
            ntohs(local.sin_port), (unsigned char *)&peers[i].sin_addr, ntohs(peers[i].sin_port));
    }
    for (size_t i = 0; i < 2; ++i) {
        close(accepted[i]); close(clients[i]); close(listeners[i]);
    }
}

static void live_ipv6(int mapped)
{
    int server = socket_reuse(mapped ? AF_INET : AF_INET6);
    struct sockaddr_in peer4 = { .sin_family = AF_INET };
    struct sockaddr_in6 peer6 = { .sin6_family = AF_INET6 }, local6_address;
    assert(inet_pton(AF_INET, "127.0.0.1", &peer4.sin_addr) == 1);
    assert(inet_pton(AF_INET6, mapped ? "::ffff:127.0.0.1" : "::1", &peer6.sin6_addr) == 1);
    socklen_t length;
    if (mapped) {
        assert(bind(server, (struct sockaddr *)&peer4, sizeof(peer4)) == 0);
        length = sizeof(peer4);
        assert(getsockname(server, (struct sockaddr *)&peer4, &length) == 0);
        peer6.sin6_port = peer4.sin_port;
    } else {
        assert(bind(server, (struct sockaddr *)&peer6, sizeof(peer6)) == 0);
        length = sizeof(peer6);
        assert(getsockname(server, (struct sockaddr *)&peer6, &length) == 0);
    }
    assert(listen(server, 1) == 0);
    int client = socket_reuse(AF_INET6), v6only = mapped ? 0 : 1;
    assert(setsockopt(client, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == 0);
    assert(connect(client, (struct sockaddr *)&peer6, sizeof(peer6)) == 0);
    int accepted = accept(server, NULL, NULL); assert(accepted >= 0);
    length = sizeof(local6_address);
    assert(getsockname(client, (struct sockaddr *)&local6_address, &length) == 0);
    assert_live_tuple(client, AF_INET6, local6_address.sin6_addr.s6_addr,
        ntohs(local6_address.sin6_port), peer6.sin6_addr.s6_addr, ntohs(peer6.sin6_port));
    if (mapped) assert_live_tuple(client, AF_INET, local6_address.sin6_addr.s6_addr + 12,
        ntohs(local6_address.sin6_port), (unsigned char *)&peer4.sin_addr, ntohs(peer4.sin_port));
    close(accepted); close(client); close(server);
}

int main(void)
{
    assert(mkdtemp(temporary_dir));
    assert(snprintf(tcp_path, sizeof(tcp_path), "%s/tcp", temporary_dir) > 0);
    assert(snprintf(tcp6_path, sizeof(tcp6_path), "%s/tcp6", temporary_dir) > 0);
    assert(atexit(cleanup) == 0);
    assert(inet_pton(AF_INET, "127.1.2.3", local4) == 1);
    assert(inet_pton(AF_INET, "198.51.100.9", remote4) == 1);
    assert(inet_pton(AF_INET6, "2001:db8:1234:5678:9abc:def0:1234:5678", local6) == 1);
    assert(inet_pton(AF_INET6, "2001:db8:ab00:cd00:ef00:102:304:506", remote6) == 1);
    ipv4_tuple_and_conflicts();
    ipv6_and_mapped();
    ipv6_scope_and_malformed();
    boundaries_and_bad_arguments();
    malformed_tables();
    live_ipv4(0);
    live_ipv4(1);
    live_ipv6(0);
    live_ipv6(1);
    puts("PASS: TCP full-tuple IPv4/IPv6/mapped, strict proc parsing, ambiguity, concurrent loopback attribution");
    return 0;
}
