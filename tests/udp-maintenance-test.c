/* Exercise the real daemon lookup/reaper call sites with owned ordinary UDP
 * sockets. No NFQUEUE, root, mock ExitLag decisions or firewall is required. */
#define main exitlag_daemon_main
#include "../backend/exitlag-netd.c"
#undef main
#include <assert.h>

static void loopback_activity(int family)
{
    int game = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int server = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(game >= 0 && server >= 0);
    struct sockaddr_storage remote = {0}, local = {0};
    socklen_t length;
    const void *local_ip, *remote_ip;
    unsigned short local_port, remote_port;
    if (family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)&remote;
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(*address);
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&remote;
        address->sin6_family = AF_INET6;
        address->sin6_addr = in6addr_loopback;
        length = sizeof(*address);
    }
    assert(bind(server, (struct sockaddr *)&remote, length) == 0);
    assert(getsockname(server, (struct sockaddr *)&remote, &length) == 0);
    assert(connect(game, (struct sockaddr *)&remote, length) == 0);
    assert(getsockname(game, (struct sockaddr *)&local, &length) == 0);
    if (family == AF_INET) {
        local_ip = &((struct sockaddr_in *)&local)->sin_addr;
        remote_ip = &((struct sockaddr_in *)&remote)->sin_addr;
        local_port = ((struct sockaddr_in *)&local)->sin_port;
        remote_port = ((struct sockaddr_in *)&remote)->sin_port;
    } else {
        local_ip = &((struct sockaddr_in6 *)&local)->sin6_addr;
        remote_ip = &((struct sockaddr_in6 *)&remote)->sin6_addr;
        local_port = ((struct sockaddr_in6 *)&local)->sin6_port;
        remote_port = ((struct sockaddr_in6 *)&remote)->sin6_port;
    }
    struct stat info;
    assert(fstat(game, &info) == 0);
    udp_reset_session();
    struct udp_endpoint *endpoint = &g_udp_endpoints[0];
    endpoint->used = 1;
    endpoint->family = family;
    endpoint->id = 123;
    endpoint->session = g_udp_session;
    endpoint->inode = (unsigned long)info.st_ino;
    assert(process_identity_read(getpid(), &endpoint->owner));
    endpoint->linux_pid = getpid();
    g_allowed_peer_uid = getuid();
    assert(resolve_pid_path((unsigned int)getpid(), endpoint->exe, sizeof(endpoint->exe)));
    unsigned char local_wire[28], original[28], proxy[28];
    unsigned short proxy_port = htons(ntohs(remote_port) == 65535 ? 1 : ntohs(remote_port) + 1);
    put_sockaddr(local_wire, family, local_ip, local_port);
    put_sockaddr(original, family, remote_ip, remote_port);
    put_sockaddr(proxy, family, remote_ip, proxy_port);
    memcpy(endpoint->local_address, local_wire, sizeof(local_wire));
    assert(udp_peers_commit(&endpoint->peers, 0, local_wire, original, proxy, monotonic_ms()));
    endpoint->last_seen_ms = 1;
    g_udp_multi = 1;
    g_shim_fd = 0; /* Lookup only checks authenticated presence; it performs no IPC. */
    g_shim_authenticated = 1;
    uint64_t before = monotonic_ms();
    assert(udp_endpoint_get(family, local_ip, local_port, remote_ip, proxy_port,
                            EXL_DIR_IN) == endpoint);
    assert(endpoint->last_seen_ms >= before);
    assert(udp_activity_idle(endpoint->last_seen_ms, monotonic_ms()) < 60000);
    /* No packet from a previously bound relay can revive a closed game socket. */
    assert(close(game) == 0);
    uint64_t seen = endpoint->last_seen_ms;
    assert(udp_endpoint_get(family, local_ip, local_port, remote_ip, proxy_port,
                            EXL_DIR_IN) == NULL);
    assert(endpoint->last_seen_ms == seen);
    assert(close(server) == 0);
    g_shim_fd = -1;
    g_shim_authenticated = 0;
}

static void retirement_budget(void)
{
    udp_reset_session();
    for (unsigned int n = 0; n < 9; ++n) {
        g_udp_endpoints[n].used = 1;
        g_udp_endpoints[n].id = 100 + n;
        /* Clock rollback is conservatively expired, without waiting a minute. */
        g_udp_endpoints[n].last_seen_ms = UINT64_MAX;
    }
    udp_reap_endpoints();
    for (unsigned int n = 0; n < 9; ++n) assert(g_udp_endpoints[n].used == (n >= 4));
    udp_reap_endpoints();
    for (unsigned int n = 0; n < 9; ++n) assert(g_udp_endpoints[n].used == (n >= 8));
    udp_reap_endpoints();
    for (unsigned int n = 0; n < 9; ++n) assert(!g_udp_endpoints[n].used);
}

static void disconnect_during_retirement(void)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    udp_reset_session();
    uint64_t session = g_udp_session;
    g_shim_fd = pair[0];
    g_shim_authenticated = 1;
    assert(close(pair[1]) == 0);
    g_udp_endpoints[0].used = 1;
    g_udp_endpoints[0].created_sent = 1;
    g_udp_endpoints[0].family = AF_INET;
    g_udp_endpoints[0].session = session;
    g_udp_endpoints[0].last_seen_ms = UINT64_MAX;
    udp_reap_endpoints();
    assert(g_shim_fd == -1 && !g_shim_authenticated);
    assert(g_udp_session != session);
    assert(!g_udp_reaper.active && g_udp_reaper.cursor == 0);
    for (unsigned int n = 0; n < UDP_ENDPOINT_MAX; ++n) assert(!g_udp_endpoints[n].used);
}

int main(void)
{
    loopback_activity(AF_INET);
    loopback_activity(AF_INET6);
    retirement_budget();
    disconnect_during_retirement();
    puts("PASS: real daemon IPv4/IPv6 reverse-proxy activity, closed socket refusal and bounded cleanup");
    return 0;
}
