/*
 * exitlag-netd -- native Linux side of the ExitLag compatibility backend.
 *
 * It watches candidate outbound TCP connections via NFQUEUE, builds the flow
 * identity, attributes the owning Linux process, and asks the Windows-side shim
 * to run ExitLag's real tcpConnectRequest callback. Observation-only is the
 * default. With --apply-tcp, a valid IPv4 destination mutation is installed as
 * one exact, short-lived 4-tuple -> address:port nftables map element before the
 * queued SYN is accepted with a one-packet priority authorization. The later
 * output NAT chain consumes it before applying DNAT. A stale map entry cannot
 * authorize a different packet; conntrack owns already translated flows.
 *
 * Design constraints honoured:
 *   - fail open: any error, timeout, missing shim or malformed reply results in
 *     NF_ACCEPT without new DNAT authorization. This does not revoke an
 *     existing conntrack translation if its proxy subsequently disappears.
 *   - no persistent firewall state: rules live in a dedicated `inet exitlag`
 *     table installed/removed by backend/nft-setup.sh and nft-teardown.sh.
 *   - NFQUEUE is bound with a bounded queue and the kernel rules use
 *     `queue ... bypass`, so if this process dies packets flow normally.
 *
 * Talks NFQUEUE over libmnl directly (libnetfilter_queue is not required).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "protocol.h"
#include "ipc_transport.h"
#include "tcp_attribution.h"
#include "process_identity.h"
#include "nfq_verdict.h"
#include "udp_attribution.h"
#include "udp_packet.h"
#include "udp_peers.h"

/*
 * Wine hands the socket fd to the application only after wineserver has created
 * it, so immediately after connect() the sole holder is wineserver and the real
 * game process is invisible. The SYN is already queued, so waiting here only
 * delays connection setup slightly, and only for flows whose sole owner is Wine
 * plumbing -- ordinary Linux processes resolve on the first attempt. The wait
 * actually taken is logged so the real distribution can be measured instead of
 * assumed.
 */
/* The shim resolves the true owner via GetExtendedTcpTable (Windows PIDs), so
   this /proc lookup is only a diagnostic aid and a fallback for non-Wine
   processes. It must stay cheap: waiting here delays the SYN. */
#define ATTR_MAX_ATTEMPTS 2
#define ATTR_STEP_MS      5

static volatile sig_atomic_t g_stop;
static int   g_queue_num = 0;
static int   g_udp_queue_num = -1;
static int   g_observe_udp;
static int   g_listen_fd = -1;
static int   g_shim_fd   = -1;
static unsigned int g_shim_windows_pid;
static unsigned long long g_next_tag = 1;
static unsigned long long g_next_endpoint;   /* seeded per run, never reused */
static unsigned long long g_flow_index;
static struct timespec g_last_flow;
static int   g_reply_timeout_ms = 300;
static int   g_no_queue;          /* IPC-only mode: never touch netfilter */
/*
 * The helper runs as root and applies destination rewrites supplied over its
 * IPC socket, so an unauthenticated peer could redirect this machine's
 * outbound connections. Only root and the desktop user who owns the ExitLag
 * process may connect; everyone else is refused at accept().
 */
static uid_t g_allowed_peer_uid = (uid_t)-1;

/*
 * Per-session IPC token. The uid check stops other accounts; it cannot stop
 * another process of the same user. The token is generated fresh on every
 * start and must be presented before any routing command is served. It prevents
 * cross-account access and stale-session replay; it does not isolate processes
 * within the owning account because they can read that account's token file.
 *
 * It is never logged, never written anywhere but that one file, and the file is
 * removed on exit. A token from a previous session is useless because a new one
 * is generated each start.
 */
static unsigned char g_session_token[EXL_TOKEN_BYTES];
static char g_token_path[PATH_MAX];
static int g_shim_authenticated;
/*
 * ExitLag redirects to its own local proxy: every redirect observed in testing
 * targeted 127.0.0.1. Allowing an arbitrary unicast destination would let an
 * authenticated peer steer this machine's traffic off-box, which is far more
 * power than the proven runtime needs. Loopback-only by default;
 * --allow-remote-redirect re-opens it for deliberate experiments.
 */
static int g_allow_remote_redirect;
/* Test-only: lets an IPC-only harness resolve PIDs the helper never reported.
   The production runners never pass it. */
static int g_allow_any_pid_resolve;
/* PIDs the helper itself reported to the shim, so PID lookups cannot be used to
   enumerate unrelated processes on the machine. */
#define OBSERVED_PID_MAX 256
static unsigned int g_observed_pids[OBSERVED_PID_MAX];
static unsigned int g_observed_pid_next;

static void remember_observed_pid(unsigned int pid)
{
    if (!pid) return;
    for (unsigned int i = 0; i < OBSERVED_PID_MAX; ++i)
        if (g_observed_pids[i] == pid) return;
    g_observed_pids[g_observed_pid_next++ % OBSERVED_PID_MAX] = pid;
}

static int pid_was_observed(unsigned int pid)
{
    for (unsigned int i = 0; i < OBSERVED_PID_MAX; ++i)
        if (g_observed_pids[i] == pid) return 1;
    return 0;
}
static int   g_apply_tcp;         /* opt-in: arm exact per-flow nft DNAT */
static int   g_apply_udp;         /* opt-in: execute one proven UDP post */
static int   g_udp_multi;         /* opt-in: correlated synchronous UDP posts */
static int   g_allow_udp_remote;
static int   g_udp_active_once;   /* lock active UDP to one eligible endpoint */
static unsigned int g_udp_active_index = 1; /* 1-based eligible endpoint ordinal */
static unsigned int g_udp_eligible_endpoint_count;
static unsigned long long g_udp_active_endpoint;
static const char *g_udp_exe;     /* optional active/observation process gate */
static const char *g_selftest;    /* synthesize one flow to this IPv4 dest */
static FILE *g_log;

/*
 * Production process-identity translation. Native keys match the kernel's
 * executable path (/proc/<pid>/exe), never process-controlled argv. The value
 * is the Windows-style
 * image path ExitLag already associates with a configured application.
 *
 * A deliberately small, fixed table keeps this path allocation-free while
 * packets are suspended in NFQUEUE.  Configuration errors fail helper startup
 * instead of silently broadening attribution.
 */
#define IDENTITY_MAP_MAX 128
#define IDENTITY_WINEPREFIX_TAG "wineprefix:"
struct identity_map_entry {
    char source[PATH_MAX];
    char target[512];
    char owner_exe[PATH_MAX]; /* prefix mappings additionally bind a real executable */
};
static struct identity_map_entry g_identity_map[IDENTITY_MAP_MAX];
static unsigned int g_identity_map_count;
static int g_identity_map_enabled;

#define UDP_ENDPOINT_MAX 2048
#define UDP_REMOTE_RULE_MAX 16
#define UDP_POST_PAYLOAD_MAX UDP_PACKET_MAX_PAYLOAD_V6
#define UDP_REINJECT_MARK 0x584c0001u
#define UDP_PEER_TTL_MS 60000u
static uint64_t g_udp_session = 1;
static uint64_t g_udp_event_tag, g_udp_event_id, g_udp_event_session;
static unsigned int g_udp_event_rules, g_udp_event_controls;
struct udp_endpoint {
    int used;
    int family;
    int created_sent;
    int connect_sent;
    unsigned long long id;
    unsigned long inode;
    struct process_identity owner;
    uint64_t session;
    struct udp_peers peers;
    int linux_pid;
    unsigned int effective_pid;
    unsigned char local_address[28];
    unsigned char first_remote[28];
    unsigned int filtering_flag;
    unsigned int remote_rule_count;
    unsigned int remote_rule_unique_count;
    unsigned char remote_rules[UDP_REMOTE_RULE_MAX][28];
    unsigned int flowctl_handle;
    int unsupported_controls;
    unsigned int active_ordinal;
    unsigned long long datagrams_out;
    unsigned long long datagrams_in;
    struct timespec last_seen;
    char exe[256];
};
static struct udp_endpoint g_udp_endpoints[UDP_ENDPOINT_MAX];

struct udp_post_capture {
    unsigned int count;
    int valid;
    unsigned int api;
    int status;
    unsigned char remote_address[28];
    unsigned int option_flags;
    unsigned int options_length;
    unsigned int payload_length;
    unsigned char payload[UDP_POST_PAYLOAD_MAX];
};
static struct udp_post_capture g_udp_post;

static void udp_reset_session(void)
{
    memset(g_udp_endpoints, 0, sizeof(g_udp_endpoints));
    memset(&g_udp_post, 0, sizeof(g_udp_post));
    g_udp_active_endpoint = 0; g_udp_eligible_endpoint_count = 0;
    if (++g_udp_session == 0) ++g_udp_session;
    g_udp_event_tag = g_udp_event_id = g_udp_event_session = 0;
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static struct udp_endpoint *udp_endpoint_by_id(unsigned long long id)
{
    for (unsigned int i = 0; i < UDP_ENDPOINT_MAX; ++i)
        if (g_udp_endpoints[i].used && g_udp_endpoints[i].id == id) return &g_udp_endpoints[i];
    return NULL;
}

static int udp_endpoint_has_remote(const struct udp_endpoint *endpoint,
                                   const unsigned char remote[28])
{
    for (unsigned int i = 0; i < endpoint->remote_rule_unique_count; ++i)
        if (memcmp(endpoint->remote_rules[i], remote, 28) == 0) return 1;
    return 0;
}

/*
 * Bound the log. A long session with a chatty game can otherwise produce
 * hundreds of megabytes; observed 11 MB from a single ExitLag session during
 * development. One previous generation is kept so a crash is still
 * investigable, and rotation is checked cheaply rather than on every line.
 */
#define LOG_MAX_BYTES_DEFAULT (8L * 1024 * 1024)
static const char *g_log_path;
static long g_log_max_bytes = LOG_MAX_BYTES_DEFAULT;

static int g_log_dir_fd = -1;
static char g_log_name[NAME_MAX + 1];

static FILE *private_log_open_at(int dir_fd, const char *name, int exclusive)
{
    int flags = O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    if (exclusive) flags |= O_EXCL;
    int fd = openat(dir_fd, name, flags, 0600);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid()) {
        close(fd); errno = EPERM; return NULL;
    }
    if (fchmod(fd, 0600) != 0) { int error = errno; close(fd); errno = error; return NULL; }
    FILE *file = fdopen(fd, "a");
    if (!file) { int error = errno; close(fd); errno = error; }
    return file;
}

/* Walk parent directories using anchored descriptors. No path component may
   be a symlink; rotation retains the same directory even if it is renamed. */
static FILE *private_log_open(const char *path)
{
    if (!path[0] || strlen(path) >= PATH_MAX) { errno = ENAMETOOLONG; return NULL; }
    char copy[PATH_MAX];
    snprintf(copy, sizeof(copy), "%s", path);
    int directory = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return NULL;
    char *save = NULL;
    char *part = strtok_r(copy, "/", &save);
    while (part) {
        char *next = strtok_r(NULL, "/", &save);
        if (!strcmp(part, "..")) { close(directory); errno = EINVAL; return NULL; }
        if (!next) {
            if (!strcmp(part, ".") || strlen(part) > NAME_MAX - 2) {
                close(directory); errno = EINVAL; return NULL;
            }
            FILE *file = private_log_open_at(directory, part, 0);
            if (!file) { int error = errno; close(directory); errno = error; return NULL; }
            g_log_dir_fd = directory;
            snprintf(g_log_name, sizeof(g_log_name), "%s", part);
            return file;
        }
        int child = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int error = errno;
        close(directory);
        if (child < 0) { errno = error; return NULL; }
        directory = child;
        part = next;
    }
    close(directory); errno = EINVAL; return NULL;
}

static void log_rotate_if_needed(void)
{
    if (!g_log || !g_log_path || g_log_dir_fd < 0) return;
    static unsigned int since_check;
    if (++since_check < 256) return;
    since_check = 0;
    struct stat opened, named;
    if (fstat(fileno(g_log), &opened) != 0 || opened.st_size < g_log_max_bytes) return;
    /* Never rename a different object substituted at the log pathname. */
    if (fstatat(g_log_dir_fd, g_log_name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        opened.st_dev != named.st_dev || opened.st_ino != named.st_ino) return;
    char rotated[NAME_MAX + 3];
    snprintf(rotated, sizeof(rotated), "%s.1", g_log_name);
    fflush(g_log);
    if (renameat(g_log_dir_fd, g_log_name, g_log_dir_fd, rotated) != 0) return;
    FILE *replacement = private_log_open_at(g_log_dir_fd, g_log_name, 1);
    if (!replacement) {
        /* Keep the already-open private inode; never follow a replacement. */
        return;
    }
    fclose(g_log);
    g_log = replacement;
    fprintf(g_log, "--- log rotated; previous private generation retained ---\n");
    fflush(g_log);
}

static void log_line(const char *fmt, ...)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char stamp[64];
    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm);

    va_list ap;
    va_start(ap, fmt);
    FILE *out = g_log ? g_log : stdout;
    fprintf(out, "%s.%03ldZ ", stamp, ts.tv_nsec / 1000000);
    vfprintf(out, fmt, ap);
    fputc('\n', out);
    fflush(out);
    va_end(ap);
    log_rotate_if_needed();
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* ---------------------------------------------------------------- process */

/*
 * Map a socket inode to the PID that really owns it.
 *
 * Wine duplicates every application socket into `wineserver`, so a naive
 * first-match-wins scan over /proc fd tables credits nearly all Wine traffic to
 * wineserver and the game process is never seen. Candidates are therefore all
 * collected and ranked:
 *
 *   best  a Windows image (argv contains ".exe") that is not wineserver
 *   next  any other process that is not wineserver/wine
 *   last  wineserver itself, only if nothing else holds the inode
 */
static int process_is_wine_plumbing(const char *pid_str)
{
    char path[320], comm[64] = "";
    snprintf(path, sizeof(path), "/proc/%s/comm", pid_str);
    FILE *f = fopen(path, "r");
    if (f) { if (!fgets(comm, sizeof(comm), f)) comm[0] = 0; fclose(f); }
    comm[strcspn(comm, "\n")] = 0;
    return !strcmp(comm, "wineserver") || !strcmp(comm, "wine") || !strcmp(comm, "wine64");
}

static int process_is_windows_image(const char *pid_str)
{
    char path[320];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    for (size_t i = 0; i < n; ) {
        if (strstr(buf + i, ".exe")) return 1;
        i += strlen(buf + i) + 1;
    }
    return 0;
}

/* Diagnostic: every process found holding the inode, with its rank. */
static char g_last_candidates[512];

static int pid_is_wine_plumbing_num(int pid)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", pid);
    return process_is_wine_plumbing(buf);
}

static int pid_for_inode(unsigned long inode, char *exe_out, size_t exe_len)
{
    if (!inode) return 0;
    char want[64];
    snprintf(want, sizeof(want), "socket:[%lu]", inode);

    DIR *proc = opendir("/proc");
    if (!proc) return 0;

    int best = 0, best_rank = -1;
    g_last_candidates[0] = 0;
    struct dirent *de;
    while ((de = readdir(proc))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char fdpath[320];
        snprintf(fdpath, sizeof(fdpath), "/proc/%s/fd", de->d_name);
        DIR *fds = opendir(fdpath);
        if (!fds) continue;

        int holds = 0;
        struct dirent *fde;
        while (!holds && (fde = readdir(fds))) {
            char link[640], target[128];
            snprintf(link, sizeof(link), "%s/%s", fdpath, fde->d_name);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = 0;
            if (!strcmp(target, want)) holds = 1;
        }
        closedir(fds);
        if (!holds) continue;

        int rank;
        if (process_is_wine_plumbing(de->d_name)) rank = 0;
        else if (process_is_windows_image(de->d_name)) rank = 2;
        else rank = 1;

        {
            char comm[64] = "";
            char cpath[320];
            snprintf(cpath, sizeof(cpath), "/proc/%s/comm", de->d_name);
            FILE *cf = fopen(cpath, "r");
            if (cf) { if (fgets(comm, sizeof(comm), cf)) comm[strcspn(comm, "\n")] = 0; fclose(cf); }
            size_t used = strlen(g_last_candidates);
            snprintf(g_last_candidates + used, sizeof(g_last_candidates) - used,
                     "%s%s:%s:r%d", used ? "," : "", de->d_name, comm, rank);
        }
        if (rank > best_rank) { best_rank = rank; best = atoi(de->d_name); }
        if (rank == 2) break;                    /* cannot do better */
    }
    closedir(proc);

    exe_out[0] = 0;
    if (best) {
        char exelink[320];
        snprintf(exelink, sizeof(exelink), "/proc/%d/exe", best);
        ssize_t m = readlink(exelink, exe_out, exe_len - 1);
        exe_out[m > 0 ? m : 0] = 0;
    }
    return best;
}

/* ------------------------------------------------------------------- ipc */

/* Idle control messages use a fresh bounded deadline. RPC paths explicitly
   share one deadline across request, nested traffic and matching response. */
static int send_frame(int fd, unsigned short type, const void *payload, unsigned int len)
{
    return exl_ipc_send_frame(fd, type, payload, len,
                              exl_ipc_deadline_after(g_reply_timeout_ms));
}

/* Constant-time compare: no early exit that could leak a prefix match. */
static int token_equal(const unsigned char *a, const unsigned char *b)
{
    unsigned char diff = 0;
    for (unsigned int i = 0; i < EXL_TOKEN_BYTES; ++i) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static void token_remove(void)
{
    if (g_token_path[0]) unlink(g_token_path);
}

/*
 * Generate this session's token and publish it where only the owning user can
 * read it. Written via a private temporary file and renamed, so a reader never
 * observes a half-written token, and created with 0600 before any content is
 * written so it is never briefly world-readable.
 */
static int token_publish(uid_t owner)
{
    int rnd = open("/dev/urandom", O_RDONLY);
    if (rnd < 0) { log_line("cannot open /dev/urandom: %s", strerror(errno)); return -1; }
    size_t got = 0;
    while (got < sizeof(g_session_token)) {
        ssize_t n = read(rnd, g_session_token + got, sizeof(g_session_token) - got);
        if (n <= 0) { close(rnd); log_line("short read from /dev/urandom"); return -1; }
        got += (size_t)n;
    }
    close(rnd);

    char tmp[PATH_MAX + 8];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_token_path);
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { log_line("cannot create token file %s: %s", tmp, strerror(errno)); return -1; }
    if (fchmod(fd, 0600) != 0) { close(fd); unlink(tmp); return -1; }
    if (geteuid() == 0 && owner != (uid_t)-1 && fchown(fd, owner, (gid_t)-1) != 0) {
        log_line("cannot give the token file to uid %u: %s", (unsigned)owner, strerror(errno));
        close(fd); unlink(tmp); return -1;
    }
    char hex[EXL_TOKEN_BYTES * 2 + 2];
    for (unsigned int i = 0; i < EXL_TOKEN_BYTES; ++i)
        snprintf(hex + i * 2, 3, "%02x", g_session_token[i]);
    hex[EXL_TOKEN_BYTES * 2] = '\n';
    ssize_t written = write(fd, hex, sizeof(hex) - 1);
    close(fd);
    if (written != (ssize_t)(sizeof(hex) - 1)) { unlink(tmp); log_line("short write to token file"); return -1; }
    if (rename(tmp, g_token_path) != 0) {
        log_line("cannot publish token file %s: %s", g_token_path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    /* Deliberately logs the path and never the value. */
    log_line("IPC session token published at %s (owner uid %u, mode 0600)",
             g_token_path, (unsigned)(owner == (uid_t)-1 ? geteuid() : owner));
    return 0;
}

/*
 * Owning uid of the process at the other end of an accepted loopback TCP
 * connection. The peer's socket appears in /proc/net/tcp{,6} as the row whose
 * local address is the peer's and whose remote address is ours; column 8 of
 * that row is the uid the kernel recorded for its owner.
 */
static int peer_uid_from_proc(const char *path, unsigned short peer_port,
                              unsigned short our_port, uid_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }   /* header */
    while (fgets(line, sizeof(line), f)) {
        char local[128], remote[128];
        unsigned int state, uid;
        /* sl local rem st tx:rx tr:when retrnsmt uid */
        if (sscanf(line, "%*d: %127s %127s %x %*x:%*x %*x:%*x %*x %u",
                   local, remote, &state, &uid) != 4) continue;
        const char *lcolon = strrchr(local, ':');
        const char *rcolon = strrchr(remote, ':');
        if (!lcolon || !rcolon) continue;
        unsigned int lport = 0, rport = 0;
        if (sscanf(lcolon + 1, "%x", &lport) != 1) continue;
        if (sscanf(rcolon + 1, "%x", &rport) != 1) continue;
        if (lport == peer_port && rport == our_port) { *out = (uid_t)uid; fclose(f); return 0; }
    }
    fclose(f);
    return -1;
}

static int peer_uid_of_connection(int fd, uid_t *out)
{
    struct sockaddr_storage peer, local;
    socklen_t peer_len = sizeof(peer), local_len = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0) return -1;
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0) return -1;
    unsigned short peer_port, our_port;
    if (peer.ss_family == AF_INET) {
        peer_port = ntohs(((struct sockaddr_in *)&peer)->sin_port);
        our_port  = ntohs(((struct sockaddr_in *)&local)->sin_port);
    } else if (peer.ss_family == AF_INET6) {
        peer_port = ntohs(((struct sockaddr_in6 *)&peer)->sin6_port);
        our_port  = ntohs(((struct sockaddr_in6 *)&local)->sin6_port);
    } else return -1;
    if (peer_uid_from_proc("/proc/net/tcp", peer_port, our_port, out) == 0) return 0;
    return peer_uid_from_proc("/proc/net/tcp6", peer_port, our_port, out);
}

static void drop_shim(const char *why)
{
    if (g_shim_fd >= 0) { close(g_shim_fd); g_shim_fd = -1; }
    g_shim_windows_pid = 0;
    g_shim_authenticated = 0;
    udp_reset_session();
    log_line("shim disconnected (%s); failing open", why);
}

static int load_identity_map(const char *map_path)
{
    FILE *f = fopen(map_path, "r");
    if (!f) {
        log_line("identity map: cannot open %s: %s", map_path, strerror(errno));
        return -1;
    }

    char line[2 * PATH_MAX + 768];
    unsigned int line_number = 0;
    while (fgets(line, sizeof(line), f)) {
        ++line_number;
        size_t length = strlen(line);
        if (length && line[length - 1] != '\n' && !feof(f)) {
            log_line("identity map: line %u is too long", line_number);
            fclose(f);
            return -1;
        }
        while (length && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = 0;
        if (!length || line[0] == '#') continue;

        char *tab = strchr(line, '\t');
        if (!tab || tab == line || !tab[1]) {
            log_line("identity map: line %u must be SOURCE<TAB>WINDOWS_PATH[<TAB>OWNER_EXE]", line_number);
            fclose(f);
            return -1;
        }
        *tab++ = 0;
        char *owner = strchr(tab, '\t');
        if (owner) *owner++ = 0;
        if (!tab[0] || (owner && (!owner[0] || strchr(owner, '\t')))) {
            log_line("identity map: line %u has empty or excess fields", line_number);
            fclose(f);
            return -1;
        }
        if (g_identity_map_count == IDENTITY_MAP_MAX) {
            log_line("identity map: more than %u entries", IDENTITY_MAP_MAX);
            fclose(f);
            return -1;
        }

        char canonical[PATH_MAX], owner_canonical[PATH_MAX] = "";
        char prefixed[PATH_MAX + sizeof(IDENTITY_WINEPREFIX_TAG)];
        const char *source = line;
        if (!strncmp(line, IDENTITY_WINEPREFIX_TAG, sizeof(IDENTITY_WINEPREFIX_TAG) - 1)) {
            /* Prefix hints are process-controlled. Require the user's exact
               approved owner executable as well as the prefix, never argv. */
            const char *dir = line + sizeof(IDENTITY_WINEPREFIX_TAG) - 1;
            struct stat st;
            if (dir[0] != '/' || !realpath(dir, canonical) ||
                stat(canonical, &st) != 0 || !S_ISDIR(st.st_mode)) {
                log_line("identity map: line %u wineprefix source is not an existing directory: %s",
                         line_number, dir);
                fclose(f);
                return -1;
            }
            snprintf(prefixed, sizeof(prefixed), "%s%s", IDENTITY_WINEPREFIX_TAG, canonical);
            source = prefixed;
            if (!owner) {
                log_line("identity map: line %u prefix mapping requires OWNER_EXE third column; "
                         "migrate to SOURCE<TAB>WINDOWS_PATH<TAB>/absolute/verified/runtime", line_number);
                fclose(f);
                return -1;
            }
            if (owner[0] != '/' || !realpath(owner, owner_canonical) ||
                stat(owner_canonical, &st) != 0 || !S_ISREG(st.st_mode) ||
                !(st.st_mode & 0111)) {
                log_line("identity map: line %u OWNER_EXE must resolve to an existing executable file", line_number);
                fclose(f);
                return -1;
            }
        } else if (line[0] == '/') {
            struct stat st;
            if (owner) {
                log_line("identity map: line %u native mapping must have exactly two columns", line_number);
                fclose(f);
                return -1;
            }
            if (!realpath(line, canonical) || stat(canonical, &st) != 0 ||
                !S_ISREG(st.st_mode) || !(st.st_mode & 0111)) {
                log_line("identity map: line %u source does not resolve to an executable file: %s", line_number, line);
                fclose(f);
                return -1;
            }
            source = canonical;
        } else {
            log_line("identity map: line %u source must be an absolute host executable path or "
                     IDENTITY_WINEPREFIX_TAG "<dir>; argv-only identities are unsafe and unsupported",
                     line_number);
            fclose(f);
            return -1;
        }

        if (strlen(source) >= sizeof(g_identity_map[0].source) ||
            strlen(tab) >= sizeof(g_identity_map[0].target)) {
            log_line("identity map: line %u source or target is too long", line_number);
            fclose(f);
            return -1;
        }
        for (unsigned int i = 0; i < g_identity_map_count; ++i) {
            if (!strcmp(g_identity_map[i].source, source) &&
                !strcmp(g_identity_map[i].owner_exe, owner_canonical)) {
                log_line("identity map: duplicate source on line %u: %s", line_number, source);
                fclose(f);
                return -1;
            }
        }

        struct identity_map_entry *entry = &g_identity_map[g_identity_map_count++];
        snprintf(entry->source, sizeof(entry->source), "%s", source);
        snprintf(entry->target, sizeof(entry->target), "%s", tab);
        snprintf(entry->owner_exe, sizeof(entry->owner_exe), "%s", owner_canonical);
    }
    if (ferror(f)) {
        log_line("identity map: read failed for %s", map_path);
        fclose(f);
        return -1;
    }
    fclose(f);
    g_identity_map_enabled = 1;
    log_line("identity map: loaded %u exact entries from %s (strict mode)",
             g_identity_map_count, map_path);
    for (unsigned int i = 0; i < g_identity_map_count; ++i)
        log_line("identity map: %s -> %s owner=%s", g_identity_map[i].source, g_identity_map[i].target,
                 g_identity_map[i].owner_exe[0] ? g_identity_map[i].owner_exe : "(native)");
    return 0;
}

/*
 * A Wine/Proton socket may also be held by its wineserver, which can reach this
 * code as the owning PID. Runtime ownership must be observed, not inferred.
 * The prefix is a useful configuration scope, not proof of a Windows image. The
 * mapping must also name the exact owner executable observed through /proc.
 * An approved loader can still launch any application in its prefix; this is
 * intentionally a same-user, prefix-wide allowlist, not image attestation.
 */
static const char *mapped_identity_for_wineprefix(unsigned int pid, const char *owner_exe)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    static char environ_buf[65536];
    ssize_t n = read(fd, environ_buf, sizeof(environ_buf) - 1);
    close(fd);
    if (n <= 0) return NULL;
    environ_buf[n] = 0;

    static const char key[] = "WINEPREFIX=";
    for (ssize_t at = 0; at < n; ) {
        const char *entry = environ_buf + at;
        size_t entry_length = strlen(entry);
        if (!strncmp(entry, key, sizeof(key) - 1)) {
            char canonical[PATH_MAX], tagged[PATH_MAX + sizeof(IDENTITY_WINEPREFIX_TAG)];
            const char *prefix = entry + sizeof(key) - 1;
            /* A relative value would resolve against this helper's cwd, not
               necessarily the socket owner's cwd, and is not reliable proof. */
            if (prefix[0] == '/' && realpath(prefix, canonical)) {
                snprintf(tagged, sizeof(tagged), "%s%s", IDENTITY_WINEPREFIX_TAG, canonical);
                for (unsigned int i = 0; i < g_identity_map_count; ++i)
                    if (!strcmp(tagged, g_identity_map[i].source) &&
                        !strcmp(owner_exe, g_identity_map[i].owner_exe))
                        return g_identity_map[i].target;
            }
            return NULL;   /* it has a prefix and none matched */
        }
        at += (ssize_t)entry_length + 1;
    }
    return NULL;
}

static const char *mapped_identity_for_pid(unsigned int pid)
{
    char path[64], value[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%u/exe", pid);
    ssize_t n = readlink(path, value, sizeof(value) - 1);
    if (n <= 0 || n == (ssize_t)sizeof(value) - 1) return NULL;
    value[n] = 0;
    for (unsigned int i = 0; i < g_identity_map_count; ++i)
        if (!g_identity_map[i].owner_exe[0] && !strcmp(value, g_identity_map[i].source))
            return g_identity_map[i].target;

    /* argv, including argv[0], is controlled by the process. Even an exact
       configured native source appearing there is not executable identity. */
    return mapped_identity_for_wineprefix(pid, value);
}


/* Resolve only explicit mappings or the kernel-reported executable. A
 * Windows-looking argv token is never proof, including when no map is loaded.
 * Wine/Proton image translation requires the user's verified map. */
static int resolve_pid_path(unsigned int pid, char *out, size_t out_len)
{
    if (!out_len) return 0;
    out[0] = 0;
    if (g_identity_map_enabled) {
        const char *mapped = mapped_identity_for_pid(pid);
        if (mapped) {
            if (strlen(mapped) >= out_len) return 0;
            memcpy(out, mapped, strlen(mapped) + 1);
            return 2; /* explicit identity translation */
        }
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/exe", pid);
    ssize_t n = readlink(path, out, out_len - 1);
    if (n > 0 && (size_t)n < out_len - 1) { out[n] = 0; return 1; }
    out[0] = 0; /* no truncated or unverifiable identity */
    return 0;
}

static void serve_resolve_pid(const unsigned char *payload, unsigned int length, exl_ipc_deadline deadline)
{
    if (length != sizeof(struct exl_resolve_pid_req)) {
        drop_shim("invalid resolve PID request size"); return;
    }
    const struct exl_resolve_pid_req *req = (const struct exl_resolve_pid_req *)payload;
    if (req->reserved) { drop_shim("invalid resolve PID reserved field"); return; }
    char exe[512];
    /* Only PIDs this helper actually reported may be resolved. Otherwise the
       lookup is a general-purpose "what is process N" oracle for anything on
       the machine, which the runtime never needs. */
    if (!g_allow_any_pid_resolve && !pid_was_observed(req->process_id)) {
        struct exl_resolve_pid_reply reply;
        reply.tag = req->tag; reply.path_length = 0; reply.reserved = 0;
        exl_ipc_send_frame(g_shim_fd, EXL_MSG_RESOLVE_PID_REPLY, &reply, sizeof(reply), deadline);
        log_line("resolve pid=%u REFUSED (not a pid this helper reported)", req->process_id);
        return;
    }
    int resolution = resolve_pid_path(req->process_id, exe, sizeof(exe));
    unsigned int len = resolution ? (unsigned int)strlen(exe) : 0;

    unsigned char frame[sizeof(struct exl_resolve_pid_reply) + 512];
    struct exl_resolve_pid_reply *reply = (struct exl_resolve_pid_reply *)frame;
    reply->tag = req->tag;
    reply->path_length = len;
    reply->reserved = 0;
    if (len) memcpy(frame + sizeof(*reply), exe, len);
    exl_ipc_send_frame(g_shim_fd, EXL_MSG_RESOLVE_PID_REPLY, frame, (unsigned int)(sizeof(*reply) + len), deadline);
    log_line("resolve pid=%u identity=%s -> %s", req->process_id,
             resolution == 2 ? "translated" : resolution == 1 ? "genuine" : "unresolved",
             len ? exe : "(unresolved)");
}

static const struct exl_udp_datagram_req *g_current_udp_req;
static const unsigned char *g_current_udp_payload;

static void wire_endpoint(char *out, size_t out_len, const unsigned char address[28])
{
    unsigned short family = (unsigned short)(address[0] | ((unsigned short)address[1] << 8));
    unsigned short port_net;
    memcpy(&port_net, address + 2, sizeof(port_net));
    char ip[INET6_ADDRSTRLEN] = "?";
    if (family == 2) inet_ntop(AF_INET, address + 4, ip, sizeof(ip));
    else if (family == 23) inet_ntop(AF_INET6, address + 8, ip, sizeof(ip));
    snprintf(out, out_len, "%s%s%s:%u", family == 23 ? "[" : "", ip,
             family == 23 ? "]" : "", (unsigned)ntohs(port_net));
}

static void handle_udp_post(const unsigned char *payload, unsigned int length)
{
    if (length < sizeof(struct exl_udp_post)) {
        if (g_current_udp_req) { ++g_udp_post.count; g_udp_post.valid = 0; }
        log_line("udp post: malformed short frame"); return;
    }
    const struct exl_udp_post *post = (const struct exl_udp_post *)payload;
    int same_event = g_current_udp_req && g_udp_event_session == g_udp_session &&
        post->event_tag == g_current_udp_req->tag && post->endpoint_id == g_current_udp_req->endpoint_id;
    if (!same_event) { log_line("udp post ignored: stale or uncorrelated event"); return; }
    ++g_udp_post.count;
    g_udp_post.valid = 0;
    unsigned int trailing = length - (unsigned int)sizeof(*post);
    if (post->options_length > trailing || post->payload_length != trailing - post->options_length ||
        post->payload_length > UDP_POST_PAYLOAD_MAX || g_udp_post.count != 1) {
        log_line("udp post: malformed lengths or repeated post"); return;
    }
    g_udp_post.valid = 1;
    g_udp_post.api = post->api; g_udp_post.status = post->status;
    memcpy(g_udp_post.remote_address, post->remote_address, 28);
    g_udp_post.option_flags = post->option_flags;
    g_udp_post.options_length = post->options_length;
    g_udp_post.payload_length = post->payload_length;
    memcpy(g_udp_post.payload, payload + sizeof(*post) + post->options_length, post->payload_length);
    char target[96]; wire_endpoint(target, sizeof(target), post->remote_address);
    log_line("%s event_tag=%llu id=0x%llx status=%d remote=%s len=%u metadata-only",
             post->api == EXL_UDP_API_POST_SEND ? "nf_udpPostSend" : "nf_udpPostReceive",
             post->event_tag, post->endpoint_id, post->status, target, post->payload_length);
}

static void handle_udp_state(const unsigned char *payload, unsigned int length)
{
    if (length < sizeof(struct exl_udp_state)) { log_line("udp state: short frame"); return; }
    const struct exl_udp_state *state = (const struct exl_udp_state *)payload;
    if (!g_udp_event_tag || g_udp_event_session != g_udp_session ||
        state->event_tag != g_udp_event_tag || state->endpoint_id != g_udp_event_id ||
        state->status != 0 || state->data_length != length - sizeof(*state)) {
        log_line("udp state ignored: failed, malformed or uncorrelated event"); return;
    }
    struct udp_endpoint *endpoint = udp_endpoint_by_id(state->endpoint_id);
    if (!endpoint || endpoint->session != g_udp_session) return;
    if (state->api == EXL_UDP_API_ADD_REMOTE_RULE) {
        ++g_udp_event_rules;
        ++endpoint->remote_rule_count;
        /* Only the historical IPv4 layout is interpreted, for the preserved
           narrow mode. Multi mode is authorized by actual posts, not this
           opaque proprietary filtering extension. No IPv6 layout is guessed. */
        if (endpoint->family == AF_INET && state->data_length == 20) {
            const unsigned char *data = payload + sizeof(*state);
            unsigned int address_host; unsigned short port, flags;
            memcpy(&address_host, data, 4); memcpy(&port, data + 16, 2); memcpy(&flags, data + 18, 2);
            unsigned char remote[28] = {2};
            unsigned int address_net = htonl(address_host);
            memcpy(remote + 2, &port, 2); memcpy(remote + 4, &address_net, 4);
            struct udp_packet_endpoint checked;
            if (flags == 1 && udp_packet_endpoint_from_wire(AF_INET, remote, &checked) == UDP_PACKET_OK &&
                !udp_endpoint_has_remote(endpoint, remote) && endpoint->remote_rule_unique_count < UDP_REMOTE_RULE_MAX)
                memcpy(endpoint->remote_rules[endpoint->remote_rule_unique_count++], remote, 28);
        }
    } else {
        ++g_udp_event_controls;
        endpoint->unsupported_controls = 1;
        if (state->api == EXL_UDP_API_SET_FLOWCTL) endpoint->flowctl_handle = state->value;
    }
    const char *name = state->api == EXL_UDP_API_ADD_REMOTE_RULE ? "nf_udpAddRemoteAddrRule" :
                       state->api == EXL_UDP_API_DISABLE_FILTERING ? "nf_udpDisableFiltering" :
                       state->api == EXL_UDP_API_ENABLE_FILTERING ? "nf_udpEnableFiltering" :
                       state->api == EXL_UDP_API_SET_FLOWCTL ? "nf_setUDPFlowCtl" : "unknown-state";
    log_line("udp state %s event_tag=%llu id=0x%llx api=%u status=%d metadata-only",
             name,
             state->event_tag, state->endpoint_id, state->api, state->status);
}

static void udp_begin_event(unsigned long long tag, unsigned long long endpoint)
{
    g_udp_event_tag = tag; g_udp_event_id = endpoint; g_udp_event_session = g_udp_session;
    g_udp_event_rules = g_udp_event_controls = 0;
}

static void udp_end_event(void)
{
    g_udp_event_tag = g_udp_event_id = g_udp_event_session = 0;
}

static int handle_nested_message(const struct exl_header *head, const unsigned char *payload,
                                 exl_ipc_deadline deadline)
{
    if (head->type == EXL_MSG_HELLO) {
        drop_shim("unexpected second HELLO");
        return -1;
    }
    if (head->type == EXL_MSG_RESOLVE_PID_REQ) {
        serve_resolve_pid(payload, head->length, deadline);
        return g_shim_fd >= 0 ? 1 : -1;
    }
    if (head->type == EXL_MSG_UDP_POST) { handle_udp_post(payload, head->length); return 1; }
    if (head->type == EXL_MSG_UDP_STATE) { handle_udp_state(payload, head->length); return 1; }
    if (head->type == EXL_MSG_PONG && head->length == 0) return 1;
    return 0;
}

static int wait_for_shim_reply(unsigned short expected_type, unsigned long long tag,
                               void *reply, unsigned int reply_length,
                               exl_ipc_deadline deadline)
{
    for (;;) {
        struct exl_header head;
        static unsigned char buf[EXL_MAX_PAYLOAD];
        if (exl_ipc_recv_frame(g_shim_fd, &head, buf, sizeof(buf), deadline) != 0) {
            log_line("shim reply failed or exceeded the %d ms RPC deadline; failing open",
                     g_reply_timeout_ms);
            /* A partial frame cannot be resumed as a new header. */
            drop_shim("reply timeout, framing error or disconnect");
            return -1;
        }
        int nested = handle_nested_message(&head, buf, deadline);
        if (nested < 0) return -1;
        if (nested) continue;
        if (head.type == expected_type) {
            if (head.length != reply_length) {
                drop_shim("invalid fixed-size RPC reply"); return -1;
            }
            unsigned long long reply_tag;
            memcpy(&reply_tag, buf, sizeof(reply_tag));
            if (reply_tag != tag) continue;
            memcpy(reply, buf, reply_length);
            return 0;
        }
        /* Unknown or stale messages do not extend the operation deadline. */
    }
}

/* Ask the real shim callback provider; synthetic tests identify themselves. */
static int ask_shim_tcp_connect(struct exl_tcp_connect_req *req, struct exl_tcp_connect_reply *reply)
{
    exl_ipc_deadline deadline = exl_ipc_deadline_after(g_reply_timeout_ms);
    if (g_shim_fd < 0) return -1;
    if (exl_ipc_send_frame(g_shim_fd, EXL_MSG_TCP_CONNECT_REQ, req, sizeof(*req), deadline) != 0) {
        drop_shim("request write failed or timed out");
        return -1;
    }
    return wait_for_shim_reply(EXL_MSG_TCP_CONNECT_REPLY, req->tag, reply, sizeof(*reply), deadline);
}

static int ask_shim_udp_lifecycle(struct exl_udp_lifecycle_req *req, int created,
                                  struct exl_udp_lifecycle_reply *reply)
{
    unsigned short request_type = created ? EXL_MSG_UDP_CREATED_REQ : EXL_MSG_UDP_CLOSED_REQ;
    unsigned short reply_type = created ? EXL_MSG_UDP_CREATED_REPLY : EXL_MSG_UDP_CLOSED_REPLY;
    exl_ipc_deadline deadline = exl_ipc_deadline_after(g_reply_timeout_ms);
    if (g_shim_fd < 0) return -1;
    if (exl_ipc_send_frame(g_shim_fd, request_type, req, sizeof(*req), deadline) != 0) {
        drop_shim("UDP lifecycle write failed or timed out"); return -1;
    }
    udp_begin_event(req->tag, req->endpoint_id);
    int result = wait_for_shim_reply(reply_type, req->tag, reply, sizeof(*reply), deadline);
    udp_end_event();
    return result;
}

static int ask_shim_udp_connect(struct exl_udp_connect_req *req,
                                struct exl_udp_connect_reply *reply)
{
    exl_ipc_deadline deadline = exl_ipc_deadline_after(g_reply_timeout_ms);
    if (g_shim_fd < 0) return -1;
    if (exl_ipc_send_frame(g_shim_fd, EXL_MSG_UDP_CONNECT_REQ, req, sizeof(*req), deadline) != 0) {
        drop_shim("UDP connect write failed or timed out"); return -1;
    }
    udp_begin_event(req->tag, req->endpoint_id);
    int result = wait_for_shim_reply(EXL_MSG_UDP_CONNECT_REPLY, req->tag, reply, sizeof(*reply), deadline);
    udp_end_event();
    return result;
}

static int ask_shim_udp_datagram(unsigned char *frame, unsigned int frame_length,
                                 struct exl_udp_datagram_reply *reply)
{
    struct exl_udp_datagram_req *req = (struct exl_udp_datagram_req *)frame;
    exl_ipc_deadline deadline = exl_ipc_deadline_after(g_reply_timeout_ms);
    if (g_shim_fd < 0) return -1;
    if (exl_ipc_send_frame(g_shim_fd, EXL_MSG_UDP_DATAGRAM_REQ, frame, frame_length, deadline) != 0) {
        drop_shim("UDP datagram write failed or timed out"); return -1;
    }
    udp_begin_event(req->tag, req->endpoint_id);
    g_current_udp_req = req;
    g_current_udp_payload = frame + sizeof(*req) + req->options_length;
    memset(&g_udp_post, 0, sizeof(g_udp_post));
    int result = wait_for_shim_reply(EXL_MSG_UDP_DATAGRAM_REPLY, req->tag, reply, sizeof(*reply), deadline);
    g_current_udp_req = NULL; g_current_udp_payload = NULL;
    udp_end_event();
    return result;
}

static void accept_shim(void)
{
    int fd = accept(g_listen_fd, NULL, NULL);
    if (fd < 0) return;

    /* Authenticate the peer before it can influence anything. Loopback alone is
       not a trust boundary: every local account can reach this port, and this
       process applies the destination rewrites its peer asks for.

       SO_PEERCRED is not available here -- it is an AF_UNIX facility and Wine's
       ws2_32 has no AF_UNIX, which is why this socket is TCP in the first
       place. The connecting socket's owning uid is instead read from the
       kernel's own accounting in /proc/net/tcp. */
    uid_t peer_uid;
    if (peer_uid_of_connection(fd, &peer_uid) != 0) {
        log_line("REFUSED shim connection: could not determine the peer's uid");
        close(fd);
        return;
    }
    if (peer_uid != 0 && peer_uid != g_allowed_peer_uid) {
        log_line("REFUSED shim connection from uid=%u (allowed: 0 or %u). "
                 "A process outside the owning account tried to drive the backend.",
                 (unsigned)peer_uid, (unsigned)g_allowed_peer_uid);
        close(fd);
        return;
    }

    /* A rejected candidate must not evict an authenticated active session.
       The entire header/body/ACK exchange shares one monotonic deadline. */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    exl_ipc_deadline deadline = exl_ipc_deadline_after(2000);
    struct exl_header head;
    static unsigned char body[EXL_MAX_PAYLOAD];
    if (exl_ipc_recv_frame(fd, &head, body, sizeof(body), deadline) != 0 ||
        head.type != EXL_MSG_HELLO || head.length != sizeof(struct exl_hello)) {
        log_line("REFUSED shim connection: no valid complete HELLO within deadline");
        close(fd);
        return;
    }
    struct exl_hello hello;
    memcpy(&hello, body, sizeof(hello));
    if (hello.version != EXL_PROTOCOL_VERSION) {
        log_line("REFUSED shim connection: version mismatch: protocol=%u (expected %u)",
                 hello.version, EXL_PROTOCOL_VERSION);
        close(fd);
        return;
    }
    if (!token_equal(hello.token, g_session_token)) {
        log_line("REFUSED shim connection from uid=%u: session token mismatch",
                 (unsigned)peer_uid);
        close(fd);
        return;
    }
    struct exl_hello_ack ack = { EXL_PROTOCOL_VERSION, (unsigned int)getpid(), 0 };
    if (exl_ipc_send_frame(fd, EXL_MSG_HELLO_ACK, &ack, sizeof(ack), deadline) != 0) {
        close(fd);
        return;
    }
    if (g_shim_fd >= 0) {
        log_line("replacing existing shim connection (authenticated peer uid=%u)", (unsigned)peer_uid);
        close(g_shim_fd);
    }
    udp_reset_session();
    g_shim_fd = fd;
    g_shim_windows_pid = hello.shim_process_id;
    g_shim_authenticated = 1;
    log_line("hello: shim protocol=%u exitlag_windows_pid=%u (token accepted)",
             hello.version, hello.shim_process_id);
}

/* --------------------------------------------------------------- nfqueue */

static struct mnl_socket *g_nl;
static unsigned int g_portid;

static void put_sockaddr(unsigned char *out, int family, const void *addr, unsigned short port_net)
{
    memset(out, 0, 28);
    if (family == AF_INET) {
        out[0] = 2; out[1] = 0;
        memcpy(out + 2, &port_net, 2);
        memcpy(out + 4, addr, 4);
    } else {
        out[0] = 23; out[1] = 0;
        memcpy(out + 2, &port_net, 2);
        memcpy(out + 8, addr, 16);
    }
}

static void format_endpoint(char *buf, size_t len, int family, const void *addr, unsigned short port_net)
{
    char ip[INET6_ADDRSTRLEN] = "?";
    inet_ntop(family, addr, ip, sizeof(ip));
    snprintf(buf, len, "%s%s%s:%u", family == AF_INET ? "" : "[", ip,
             family == AF_INET ? "" : "]", ntohs(port_net));
}

static int udp_emit_lifecycle(struct udp_endpoint *endpoint, int created)
{
    struct exl_udp_lifecycle_req req;
    memset(&req, 0, sizeof(req));
    req.tag = g_next_tag++; req.endpoint_id = endpoint->id;
    req.process_id = (unsigned int)endpoint->linux_pid;
    remember_observed_pid(req.process_id);
    req.ip_family = (unsigned short)(endpoint->family == AF_INET ? 2 : 23);
    memcpy(req.local_address, endpoint->local_address, 28);
    struct exl_udp_lifecycle_reply reply;
    memset(&reply, 0, sizeof(reply));
    if (ask_shim_udp_lifecycle(&req, created, &reply) != 0 ||
        reply.verdict > EXL_VERDICT_MUTATED || reply.ip_family != req.ip_family) {
        log_line("udp %s tag=%llu id=0x%llx pid=%d exe=%s | no shim reply; packet remains unchanged",
                 created ? "created" : "closed", req.tag, endpoint->id, endpoint->linux_pid,
                 endpoint->exe[0] ? endpoint->exe : "?");
        return -1;
    }
    endpoint->effective_pid = reply.process_id;
    char local[96]; wire_endpoint(local, sizeof(local), endpoint->local_address);
    log_line("udp %s tag=%llu id=0x%llx local=%s linux_pid=%d exe=%s effective_pid=%u "
             "verdict=%u mutated_info=%u remote_rules=%u flowctl=%u",
             created ? "udpCreated" : "udpClosed", req.tag, endpoint->id, local,
             endpoint->linux_pid, endpoint->exe[0] ? endpoint->exe : "?",
             reply.process_id, reply.verdict, reply.mutated_info,
             endpoint->remote_rule_count, endpoint->flowctl_handle);
    return 0;
}

static int udp_owner_valid(const struct udp_endpoint *endpoint)
{
    char current[256];
    int identity = resolve_pid_path((unsigned int)endpoint->owner.pid, current, sizeof(current));
    return endpoint->used && endpoint->session == g_udp_session &&
        endpoint->owner.uid == g_allowed_peer_uid &&
        identity && (!g_udp_multi || !g_identity_map_enabled || identity == 2) &&
        !strcmp(current, endpoint->exe) &&
        process_identity_holds_socket(&endpoint->owner, endpoint->inode);
}

static int udp_tuple_valid(const struct udp_endpoint *endpoint,
                           const unsigned char local[28], const unsigned char remote[28])
{
    struct udp_packet_endpoint l, r;
    unsigned long inode = 0;
    return udp_packet_endpoint_from_wire(endpoint->family, local, &l) == UDP_PACKET_OK &&
        udp_packet_endpoint_from_wire(endpoint->family, remote, &r) == UDP_PACKET_OK &&
        udp_attribution_lookup(endpoint->family, l.address, ntohs(l.port_net),
                               r.address, ntohs(r.port_net), &inode) == UDP_ATTR_FOUND &&
        inode == endpoint->inode && udp_owner_valid(endpoint);
}

static void udp_retire(struct udp_endpoint *endpoint, const char *reason)
{
    unsigned long long id = endpoint->id;
    unsigned long long out = endpoint->datagrams_out, in = endpoint->datagrams_in;
    unsigned int rules = endpoint->remote_rule_unique_count;
    if (endpoint->created_sent && endpoint->session == g_udp_session)
        udp_emit_lifecycle(endpoint, 0);
    memset(endpoint, 0, sizeof(*endpoint));
    log_line("udp endpoint release id=0x%llx reason=%s datagrams={out=%llu,in=%llu} remote_rules_deleted=%u",
             id, reason, out, in, rules);
}

static struct udp_endpoint *udp_reverse_endpoint(int family, const unsigned char local[28],
                                                 const unsigned char remote[28])
{
    struct udp_endpoint *found = NULL;
    uint64_t now = monotonic_ms();
    for (unsigned int i = 0; i < UDP_ENDPOINT_MAX; ++i) {
        struct udp_endpoint *endpoint = &g_udp_endpoints[i];
        if (!endpoint->used || endpoint->family != family || endpoint->session != g_udp_session) continue;
        for (int j = 0; j < UDP_PEERS_MAX; ++j) {
            struct udp_peer *peer = &endpoint->peers.entries[j];
            if (!udp_peer_matches(peer, local, remote, now, UDP_PEER_TTL_MS) ||
                !udp_tuple_valid(endpoint, local, peer->original)) continue;
            if (found && found != endpoint) return NULL;
            found = endpoint;
        }
    }
    return found;
}

static int udp_post_is_loopback(const struct udp_packet_endpoint *address);

static struct udp_endpoint *udp_endpoint_get(int family, const void *local_ip,
                                              unsigned short local_port_net,
                                              const void *remote_ip, unsigned short remote_port_net,
                                              int direction)
{
    if (g_shim_fd < 0 || !g_shim_authenticated) return NULL;
    unsigned char local[28], remote[28];
    put_sockaddr(local, family, local_ip, local_port_net);
    put_sockaddr(remote, family, remote_ip, remote_port_net);
    if (g_udp_multi && direction == EXL_DIR_IN) {
        struct udp_packet_endpoint peer;
        if (udp_packet_endpoint_from_wire(family, remote, &peer) != UDP_PACKET_OK) return NULL;
        /* Local proxy replies need a previously authorized binding. Do not
           inspect unrelated desktop loopback UDP just because input is queued. */
        if (udp_post_is_loopback(&peer)) return udp_reverse_endpoint(family, local, remote);
    }
    unsigned long inode = 0;
    enum udp_attribution_result attribution = udp_attribution_lookup(
        family, local_ip, ntohs(local_port_net), remote_ip, ntohs(remote_port_net), &inode);
    if (attribution == UDP_ATTR_NONE && direction == EXL_DIR_IN && g_udp_multi) {
        struct udp_endpoint *reverse = udp_reverse_endpoint(family, local, remote);
        if (reverse) clock_gettime(CLOCK_MONOTONIC, &reverse->last_seen);
        return reverse;
    }
    if (attribution != UDP_ATTR_FOUND) return NULL;
    char exe[256] = "";
    int pid = pid_for_inode(inode, exe, sizeof(exe));
    struct process_identity owner;
    if (!pid || !process_identity_read((pid_t)pid, &owner) || owner.uid != g_allowed_peer_uid ||
        !process_identity_holds_socket(&owner, inode)) return NULL;
    int identity = resolve_pid_path((unsigned int)pid, exe, sizeof(exe));
    if (!identity || (g_udp_multi && g_identity_map_enabled && identity != 2)) return NULL;
    if (g_udp_exe && !strcasestr(exe, g_udp_exe)) return NULL;

    for (unsigned int i = 0; i < UDP_ENDPOINT_MAX; ++i) {
        struct udp_endpoint *endpoint = &g_udp_endpoints[i];
        if (!endpoint->used || endpoint->family != family) continue;
        if (endpoint->inode == inode && endpoint->owner.pid == owner.pid &&
            endpoint->owner.uid == owner.uid && endpoint->owner.start_time == owner.start_time &&
            endpoint->session == g_udp_session) {
            if (strcmp(endpoint->exe, exe)) {
                udp_retire(endpoint, "executable-identity-changed");
                continue;
            }
            clock_gettime(CLOCK_MONOTONIC, &endpoint->last_seen);
            return endpoint;
        }
        if (!memcmp(endpoint->local_address, local, 28) && !udp_owner_valid(endpoint))
            udp_retire(endpoint, "socket-or-process-replaced");
    }
    if (g_shim_fd < 0 || !process_identity_holds_socket(&owner, inode)) return NULL;
    struct udp_endpoint *endpoint = NULL;
    for (unsigned int i = 0; i < UDP_ENDPOINT_MAX; ++i)
        if (!g_udp_endpoints[i].used) { endpoint = &g_udp_endpoints[i]; break; }
    if (!endpoint || !g_next_endpoint) {
        log_line("udp endpoint capacity exhausted; accepting unchanged"); return NULL;
    }
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->used = 1; endpoint->family = family; endpoint->id = g_next_endpoint++;
    endpoint->inode = inode; endpoint->owner = owner; endpoint->linux_pid = pid;
    endpoint->session = g_udp_session; endpoint->filtering_flag = 0x12;
    memcpy(endpoint->local_address, local, 28);
    snprintf(endpoint->exe, sizeof(endpoint->exe), "%s", exe);
    clock_gettime(CLOCK_MONOTONIC, &endpoint->last_seen);
    return endpoint;
}

static int udp_emit_connect(struct udp_endpoint *endpoint, const unsigned char remote_address[28])
{
    struct exl_udp_connect_req req;
    memset(&req, 0, sizeof(req));
    req.tag = g_next_tag++; req.endpoint_id = endpoint->id;
    req.process_id = (unsigned int)endpoint->linux_pid;
    remember_observed_pid(req.process_id);
    req.filtering_flag = endpoint->filtering_flag;
    req.ip_family = (unsigned short)(endpoint->family == AF_INET ? 2 : 23);
    memcpy(req.local_address, endpoint->local_address, 28);
    memcpy(req.remote_address, remote_address, 28);
    struct exl_udp_connect_reply reply;
    memset(&reply, 0, sizeof(reply));
    if (ask_shim_udp_connect(&req, &reply) != 0 ||
        reply.verdict > EXL_VERDICT_MUTATED) return -1;
    endpoint->effective_pid = reply.process_id;
    endpoint->filtering_flag = reply.filtering_flag;
    memcpy(endpoint->first_remote, remote_address, 28);
    char local[96], remote[96], after[96];
    wire_endpoint(local, sizeof(local), endpoint->local_address);
    wire_endpoint(remote, sizeof(remote), remote_address);
    wire_endpoint(after, sizeof(after), reply.remote_address);
    log_line("udp udpConnectRequest tag=%llu id=0x%llx linux=%s -> %s linux_pid=%d exe=%s "
             "effective_pid=%u flag=0x%x->0x%x remote_after=%s verdict=%u mutated={flag=%u,remote=%u} | OBSERVE unchanged",
             req.tag, endpoint->id, local, remote, endpoint->linux_pid,
             endpoint->exe[0] ? endpoint->exe : "?", reply.process_id,
             req.filtering_flag, reply.filtering_flag, after, reply.verdict,
             reply.mutated_flag, reply.mutated_remote);
    return 0;
}

static void udp_reap_endpoints(void)
{
    static time_t last_reap;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec == last_reap) return;
    last_reap = now.tv_sec;
    for (unsigned int i = 0; i < UDP_ENDPOINT_MAX; ++i) {
        struct udp_endpoint *endpoint = &g_udp_endpoints[i];
        if (!endpoint->used) continue;
        long long idle = now.tv_sec - endpoint->last_seen.tv_sec;
        if (idle >= 60 || (idle >= 2 && !udp_owner_valid(endpoint)))
            udp_retire(endpoint, idle >= 60 ? "idle-timeout" : "socket-or-process-closed");
    }
}

static void send_verdict_priority(int queue_num, unsigned int packet_id,
                                  unsigned int verdict, const uint32_t *priority)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    size_t length = nfq_verdict_build(buf, sizeof(buf), (uint16_t)queue_num,
                                    packet_id, verdict, priority);
    if (!length) {
        log_line("verdict construction failed");
        return;
    }
    if (mnl_socket_sendto(g_nl, buf, length) < 0)
        log_line("verdict send failed: %s", strerror(errno));
}

static void send_verdict(int queue_num, unsigned int packet_id, unsigned int verdict)
{
    send_verdict_priority(queue_num, packet_id, verdict, NULL);
}

static int udp_reinject_post_send(const struct udp_packet_view *view,
                                  const struct udp_post_capture *post, uint32_t priority)
{
    struct udp_packet_endpoint target;
    if (udp_packet_endpoint_from_wire(view->src.family, post->remote_address, &target) != UDP_PACKET_OK)
        return -1;
    static int raw[2] = {-1, -1};
    int index = view->src.family == AF_INET ? 0 : 1;
    if (raw[index] < 0) {
        int fd = socket(view->src.family, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
        if (fd < 0) return -1;
        int one = 1; unsigned int mark = UDP_REINJECT_MARK;
        int level = index ? IPPROTO_IPV6 : IPPROTO_IP;
        int option = index ? IPV6_HDRINCL : IP_HDRINCL;
        if (setsockopt(fd, level, option, &one, sizeof(one)) < 0 ||
            setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
            close(fd); return -1;
        }
        raw[index] = fd;
    }
    if (setsockopt(raw[index], SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0)
        return -1;
    static unsigned char packet[UDP_PACKET_MAX_SIZE];
    size_t length = 0;
    if (udp_packet_build(packet, sizeof(packet), &view->src, &target,
                         post->payload, post->payload_length,
                         view->traffic_class, view->hop_limit, &length) != UDP_PACKET_OK)
        return -1;
    struct sockaddr_storage destination = {0};
    socklen_t address_length;
    if (index) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&destination;
        a->sin6_family = AF_INET6;
        memcpy(&a->sin6_addr, target.address, 16);
        address_length = sizeof(*a);
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&destination;
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr, target.address, 4);
        address_length = sizeof(*a);
    }
    ssize_t result = sendto(raw[index], packet, length, MSG_DONTWAIT,
                            (struct sockaddr *)&destination, address_length);
    return result == (ssize_t)length ? 0 : -1;
}

static int udp_post_is_loopback(const struct udp_packet_endpoint *address)
{
    if (address->family == AF_INET) return address->address[0] == 127;
    struct in6_addr v6;
    memcpy(&v6, address->address, 16);
    return IN6_IS_ADDR_LOOPBACK(&v6);
}

static int udp_outgoing_peer_slot(struct udp_endpoint *endpoint, const unsigned char local[28],
                                  const unsigned char original[28], const unsigned char posted[28])
{
    uint64_t now = monotonic_ms();
    struct udp_packet_endpoint l, target;
    unsigned long target_inode = 0;
    if (udp_packet_endpoint_from_wire(endpoint->family, local, &l) != UDP_PACKET_OK ||
        udp_packet_endpoint_from_wire(endpoint->family, posted, &target) != UDP_PACKET_OK) return -1;
    enum udp_attribution_result owner = udp_attribution_lookup(endpoint->family,
        l.address, ntohs(l.port_net), target.address, ntohs(target.port_net), &target_inode);
    if (owner == UDP_ATTR_INVALID || owner == UDP_ATTR_AMBIGUOUS ||
        (owner == UDP_ATTR_FOUND && target_inode != endpoint->inode)) return -1;
    /* Different connected sockets may share a local port. They cannot both
       translate to the same relay tuple without a proven payload demultiplexer. */
    for (unsigned int i = 0; i < UDP_ENDPOINT_MAX; ++i) {
        struct udp_endpoint *other = &g_udp_endpoints[i];
        if (!other->used || other == endpoint || other->family != endpoint->family ||
            other->session != g_udp_session) continue;
        for (int j = 0; j < UDP_PEERS_MAX; ++j)
            if (udp_peer_matches(&other->peers.entries[j], local, posted, now, UDP_PEER_TTL_MS) &&
                udp_owner_valid(other)) return -1;
    }
    return udp_peers_prepare(&endpoint->peers, local, original, posted, now, UDP_PEER_TTL_MS);
}

static int udp_packet_owner_valid(struct udp_endpoint *endpoint, const unsigned char local[28],
                                   const unsigned char remote[28], int direction)
{
    if (udp_tuple_valid(endpoint, local, remote)) return 1;
    return g_udp_multi && direction == EXL_DIR_IN &&
        udp_reverse_endpoint(endpoint->family, local, remote) == endpoint;
}

static int udp_replace_receive(int queue, unsigned int packet_id,
                               const struct udp_packet_view *view,
                               const struct udp_post_capture *post)
{
    struct udp_packet_endpoint source;
    if (udp_packet_endpoint_from_wire(view->dst.family, post->remote_address, &source) != UDP_PACKET_OK)
        return 0;
    static unsigned char packet[UDP_PACKET_MAX_SIZE];
    static unsigned char verdict[UDP_PACKET_MAX_SIZE + 256];
    size_t length = 0;
    if (udp_packet_build(packet, sizeof(packet), &source, &view->dst,
                         post->payload, post->payload_length,
                         view->traffic_class, view->hop_limit, &length) != UDP_PACKET_OK) return 0;
    size_t encoded = nfq_verdict_build_packet(verdict, sizeof(verdict), (uint16_t)queue,
                                              packet_id, NF_ACCEPT, NULL, packet, length);
    if (!encoded) return 0;
    if (mnl_socket_sendto(g_nl, verdict, encoded) < 0) {
        log_line("UDP receive verdict send failed: %s", strerror(errno));
        return 0;
    }
    return 1;
}

static void observe_udp_packet(int queue_num, unsigned int packet_id,
                               const struct udp_packet_view *view, unsigned int hook,
                               unsigned int original_mark, uint32_t original_priority)
{
    int direction = hook == NF_INET_LOCAL_OUT ? EXL_DIR_OUT :
                    hook == NF_INET_LOCAL_IN ? EXL_DIR_IN : 0;
    if (!direction || (g_udp_multi && original_mark)) {
        send_verdict(queue_num, packet_id, NF_ACCEPT); return;
    }
    const struct udp_packet_endpoint *local = direction == EXL_DIR_OUT ? &view->src : &view->dst;
    const struct udp_packet_endpoint *remote = direction == EXL_DIR_OUT ? &view->dst : &view->src;
    int family = local->family;
    struct udp_endpoint *endpoint = udp_endpoint_get(family, local->address, local->port_net,
                                                    remote->address, remote->port_net, direction);
    if (!endpoint) { send_verdict(queue_num, packet_id, NF_ACCEPT); return; }
    if (!endpoint->created_sent) {
        if (udp_emit_lifecycle(endpoint, 1) != 0 || !udp_owner_valid(endpoint)) {
            send_verdict(queue_num, packet_id, NF_ACCEPT); return;
        }
        endpoint->created_sent = 1;
    }
    if (g_udp_active_once && endpoint->active_ordinal == 0)
        endpoint->active_ordinal = ++g_udp_eligible_endpoint_count;
    unsigned char local_address[28], remote_address[28];
    put_sockaddr(local_address, family, local->address, local->port_net);
    put_sockaddr(remote_address, family, remote->address, remote->port_net);
    if (!udp_packet_owner_valid(endpoint, local_address, remote_address, direction)) {
        send_verdict(queue_num, packet_id, NF_ACCEPT); return;
    }
    if (direction == EXL_DIR_OUT && !endpoint->connect_sent) {
        if (udp_emit_connect(endpoint, remote_address) != 0 || !udp_owner_valid(endpoint)) {
            send_verdict(queue_num, packet_id, NF_ACCEPT); return;
        }
        endpoint->connect_sent = 1;
    }
    static unsigned char frame[EXL_MAX_PAYLOAD];
    if (view->payload_length > sizeof(frame) - sizeof(struct exl_udp_datagram_req)) {
        send_verdict(queue_num, packet_id, NF_ACCEPT); return;
    }
    struct exl_udp_datagram_req *req = (struct exl_udp_datagram_req *)frame;
    memset(req, 0, sizeof(*req));
    req->tag = g_next_tag++; req->endpoint_id = endpoint->id;
    req->process_id = (unsigned int)endpoint->linux_pid;
    req->direction = (unsigned char)direction; req->ip_family = family == AF_INET ? 2 : 23;
    remember_observed_pid(req->process_id);
    /* A wildcard socket can use several interfaces. The packet's actual local
       address, not the lifecycle's first observed address, owns this datagram. */
    memcpy(req->local_address, local_address, 28); memcpy(req->remote_address, remote_address, 28);
    req->payload_length = (unsigned int)view->payload_length;
    memcpy(frame + sizeof(*req), view->payload, view->payload_length);
    if (direction == EXL_DIR_OUT) ++endpoint->datagrams_out; else ++endpoint->datagrams_in;
    struct exl_udp_datagram_reply reply = {0};
    uint64_t session = g_udp_session;
    int have_reply = ask_shim_udp_datagram(frame, (unsigned int)(sizeof(*req) + view->payload_length), &reply) == 0;
    unsigned int verdict = NF_ACCEPT;
    int replaced = 0;
    const char *decision = g_apply_udp ? "ACCEPT unchanged (UDP fail-open)" : "ACCEPT unchanged (UDP observe)";
    int common = g_apply_udp && have_reply && session == g_udp_session &&
        reply.verdict <= EXL_VERDICT_MUTATED && !reply.reserved && reply.post_count == 1 &&
        reply.control_count == 0 && g_udp_event_controls == 0 && !reply.mutated_options &&
        !endpoint->unsupported_controls && endpoint->flowctl_handle == 0 &&
        g_udp_post.count == 1 && g_udp_post.valid && g_udp_post.status == 0 &&
        g_udp_post.option_flags == 0 && g_udp_post.options_length == 0 &&
        udp_packet_owner_valid(endpoint, local_address, remote_address, direction);
    struct udp_packet_endpoint post_remote;
    if (common && udp_packet_endpoint_from_wire(family, g_udp_post.remote_address, &post_remote) != UDP_PACKET_OK)
        common = 0;
    if (g_udp_multi && common) {
        if (direction == EXL_DIR_OUT && g_udp_post.api == EXL_UDP_API_POST_SEND) {
            int changed = memcmp(remote_address, g_udp_post.remote_address, 28) != 0;
            int allowed = !changed || g_allow_udp_remote || g_allow_remote_redirect || udp_post_is_loopback(&post_remote);
            int slot = allowed ? udp_outgoing_peer_slot(endpoint, local_address, remote_address,
                                                       g_udp_post.remote_address) : -1;
            if (slot >= 0 && udp_reinject_post_send(view, &g_udp_post, original_priority) == 0) {
                udp_peers_commit(&endpoint->peers, slot, local_address, remote_address,
                                  g_udp_post.remote_address, monotonic_ms());
                verdict = NF_DROP;
                decision = "DROP original; POST_SEND applied (UDP multi)";
            } else decision = "ACCEPT unchanged (UDP target, reverse binding or raw send unavailable)";
        } else if (direction == EXL_DIR_IN && g_udp_post.api == EXL_UDP_API_POST_RECEIVE &&
                   udp_tuple_valid(endpoint, local_address, g_udp_post.remote_address)) {
            replaced = udp_replace_receive(queue_num, packet_id, view, &g_udp_post);
            if (replaced) {
                uint64_t now = monotonic_ms();
                for (int i = 0; i < UDP_PEERS_MAX; ++i) {
                    struct udp_peer *peer = &endpoint->peers.entries[i];
                    if (udp_peer_matches(peer, local_address, remote_address, now, UDP_PEER_TTL_MS) &&
                        !memcmp(peer->original, g_udp_post.remote_address, 28)) peer->last_ms = now;
                }
            }
            decision = replaced ? "POST_RECEIVE applied (UDP multi)" : "ACCEPT unchanged (UDP receive replacement failed)";
        }
    } else if (!g_udp_multi && common) {
        int same_remote = !memcmp(g_udp_post.remote_address, remote_address, 28);
        int same_payload = g_udp_post.payload_length == view->payload_length &&
            !memcmp(g_udp_post.payload, view->payload, view->payload_length);
        int selected = !g_udp_active_once || (g_udp_active_endpoint && g_udp_active_endpoint == endpoint->id) ||
            (!g_udp_active_endpoint && endpoint->active_ordinal == g_udp_active_index);
        if (same_remote && same_payload && !reply.mutated_remote && !reply.mutated_payload &&
            reply.verdict == EXL_VERDICT_UNCHANGED && udp_endpoint_has_remote(endpoint, remote_address) && selected) {
            if (direction == EXL_DIR_OUT && family == AF_INET &&
                g_udp_post.api == EXL_UDP_API_POST_SEND && reply.remote_rule_count == 1 && g_udp_event_rules == 1 &&
                udp_reinject_post_send(view, &g_udp_post, original_priority) == 0) {
                g_udp_active_endpoint = endpoint->id; verdict = NF_DROP;
                decision = "DROP original; POST_SEND reinjected with bypass mark";
            } else if (direction == EXL_DIR_IN && g_udp_post.api == EXL_UDP_API_POST_RECEIVE && reply.remote_rule_count == 0)
                decision = "ACCEPT POST_RECEIVE reply to original socket";
        }
    }
    char local_text[96], remote_text[96];
    wire_endpoint(local_text, sizeof(local_text), local_address);
    wire_endpoint(remote_text, sizeof(remote_text), remote_address);
    log_line("udp %s tag=%llu id=0x%llx linux=%s -> %s linux_pid=%u len=%u metadata-only | %s",
             direction == EXL_DIR_OUT ? "udpSend" : "udpReceive", req->tag, req->endpoint_id,
             local_text, remote_text, req->process_id, req->payload_length, decision);
    if (!replaced) send_verdict(queue_num, packet_id, verdict);
}

/*
 * Install one exact redirect decision in the map created by nft-setup.sh.
 *
 * The key contains the complete original IPv4 4-tuple, rather than merely the
 * remote endpoint: two simultaneous connections to the same game server may
 * receive different callback results and must never share policy. The element
 * expires shortly after this SYN. Once the NAT chain sees the SYN, conntrack
 * retains the translation for all later packets and no persistent map entry is
 * needed.
 *
 * A trusted absolute nft path is invoked directly (never through a shell), and every token in
 * the command is produced by inet_ntop or an integer conversion. A failed map
 * update is a fail-open condition: the caller supplies no packet authorization.
 * A successful update alone is insufficient: the current verdict must also
 * carry the transient priority bit consumed by output_nat.
 */
/*
 * Install one exact 4-tuple DNAT element. The only difference between families
 * is the map name and the textual address form, so the same code path serves
 * both rather than a parallel IPv6 implementation.
 */
static int nft_arm_tcp_redirect(int family, const void *src, unsigned short sport_net,
                                const void *dst, unsigned short dport_net,
                                const void *new_dst, unsigned short new_dport_net)
{
    const char *map = (family == AF_INET6) ? "tcp_redirect_v6" : "tcp_redirect_v4";
    char src_text[INET6_ADDRSTRLEN], dst_text[INET6_ADDRSTRLEN], new_text[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, src, src_text, sizeof(src_text)) ||
        !inet_ntop(family, dst, dst_text, sizeof(dst_text)) ||
        !inet_ntop(family, new_dst, new_text, sizeof(new_text)))
        return -1;

    char command[768];
    int length = snprintf(command, sizeof(command),
        "destroy element inet exitlag %s { %s . %u . %s . %u }\n"
        "add element inet exitlag %s { "
        "%s . %u . %s . %u timeout 10s : %s . %u }\n",
        map, src_text, (unsigned)ntohs(sport_net), dst_text, (unsigned)ntohs(dport_net),
        map, src_text, (unsigned)ntohs(sport_net), dst_text, (unsigned)ntohs(dport_net),
        new_text, (unsigned)ntohs(new_dport_net));
    if (length <= 0 || (size_t)length >= sizeof(command)) return -1;

    int input[2];
    if (pipe(input) != 0) return -1;
    pid_t child = fork();
    if (child < 0) { close(input[0]); close(input[1]); return -1; }
    if (child == 0) {
        if (dup2(input[0], STDIN_FILENO) < 0) _exit(126);
        close(input[0]); close(input[1]);
        /* The compile-time override is for packaged/isolated test builds.
           Never search a root helper's caller-controlled PATH. */
#ifdef EXL_NFT_PATH
        execl(EXL_NFT_PATH, "nft", "-f", "-", (char *)NULL);
#else
        execl("/usr/sbin/nft", "nft", "-f", "-", (char *)NULL);
        execl("/usr/bin/nft", "nft", "-f", "-", (char *)NULL);
#endif
        _exit(127);
    }

    close(input[0]);
    size_t written = 0;
    while (written < (size_t)length) {
        ssize_t n = write(input[1], command + written, (size_t)length - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        written += (size_t)n;
    }
    close(input[1]);

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return written == (size_t)length && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int parse_attrs(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);
    if (mnl_attr_type_valid(attr, NFQA_MAX) < 0) return MNL_CB_OK;
    tb[type] = attr;
    return MNL_CB_OK;
}

static int on_packet(const struct nlmsghdr *nlh, void *data)
{
    (void)data;
    const struct nlattr *tb[NFQA_MAX + 1] = { 0 };
    mnl_attr_parse(nlh, sizeof(struct nfgenmsg), parse_attrs, tb);
    if (!tb[NFQA_PACKET_HDR]) return MNL_CB_OK;

    struct nfqnl_msg_packet_hdr *ph = mnl_attr_get_payload(tb[NFQA_PACKET_HDR]);
    unsigned int packet_id = ntohl(ph->packet_id);
    const struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
    int queue_num = (int)ntohs(nfg->res_id);

    /* Every rejection or malformed input below deliberately fails open. */
    if (!tb[NFQA_PAYLOAD]) { send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK; }

    unsigned char *payload = mnl_attr_get_payload(tb[NFQA_PAYLOAD]);
    unsigned int payload_len = mnl_attr_get_payload_len(tb[NFQA_PAYLOAD]);
    if (payload_len < 20) { send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK; }

    int family; const void *src, *dst; const unsigned char *l4; unsigned int l4_len; unsigned char proto;
    if ((payload[0] >> 4) == 4) {
        struct iphdr *ip = (struct iphdr *)payload;
        unsigned int ihl = ip->ihl * 4u;
        if (ihl < 20u || payload_len < ihl) { send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK; }
        family = AF_INET; src = &ip->saddr; dst = &ip->daddr; proto = ip->protocol;
        l4 = payload + ihl; l4_len = payload_len - ihl;
    } else if ((payload[0] >> 4) == 6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)payload;
        if (payload_len < 40u) { send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK; }
        family = AF_INET6; src = &ip6->ip6_src; dst = &ip6->ip6_dst;
        proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        l4 = payload + 40; l4_len = payload_len - 40;
    } else { send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK; }

    if (g_observe_udp && queue_num == g_udp_queue_num && proto == IPPROTO_UDP) {
        unsigned int skb_info = 0, mark = 0;
        uint32_t priority = 0;
        if ((tb[NFQA_SKB_INFO] && mnl_attr_get_payload_len(tb[NFQA_SKB_INFO]) != 4) ||
            (tb[NFQA_MARK] && mnl_attr_get_payload_len(tb[NFQA_MARK]) != 4) ||
            (tb[NFQA_CAP_LEN] && (mnl_attr_get_payload_len(tb[NFQA_CAP_LEN]) != 4 ||
             ntohl(mnl_attr_get_u32(tb[NFQA_CAP_LEN])) != payload_len))) {
            send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK;
        }
        if (!nfq_priority_read(tb[NFQA_PRIORITY], &priority)) {
            send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK;
        }
        if (tb[NFQA_SKB_INFO]) skb_info = ntohl(mnl_attr_get_u32(tb[NFQA_SKB_INFO]));
        if (tb[NFQA_MARK]) mark = ntohl(mnl_attr_get_u32(tb[NFQA_MARK]));
        struct udp_packet_view view;
        if ((skb_info & NFQA_SKB_GSO) ||
            (ph->hook == NF_INET_LOCAL_IN && (skb_info & NFQA_SKB_CSUMNOTREADY)) ||
            udp_packet_parse(payload, payload_len, &view) != UDP_PACKET_OK ||
            (ph->hook == NF_INET_LOCAL_IN && !udp_packet_checksums_valid(payload, payload_len))) {
            send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK;
        }
        observe_udp_packet(queue_num, packet_id, &view, ph->hook, mark, priority);
        return MNL_CB_OK;
    }
    if (queue_num != g_queue_num) {
        send_verdict(queue_num, packet_id, NF_ACCEPT); return MNL_CB_OK;
    }

    if (proto != IPPROTO_TCP || l4_len < sizeof(struct tcphdr)) {
        send_verdict(queue_num, packet_id, NF_ACCEPT);
        return MNL_CB_OK;
    }
    const struct tcphdr *tcp = (const struct tcphdr *)l4;
    if (!tcp->syn || tcp->ack) {          /* only the first SYN starts a flow */
        send_verdict(queue_num, packet_id, NF_ACCEPT);
        return MNL_CB_OK;
    }

    uint32_t packet_priority = 0;
    if (!nfq_priority_read(tb[NFQA_PRIORITY], &packet_priority) ||
        (packet_priority & EXL_TCP_AUTH_PRIORITY)) {
        /* The owned queue chain clears this bit before enqueueing. Never
           authorize an unverified priority attribute or foreign queue path. */
        packet_priority &= ~EXL_TCP_AUTH_PRIORITY;
        send_verdict_priority(queue_num, packet_id, NF_ACCEPT, &packet_priority);
        return MNL_CB_OK;
    }

    unsigned char local_ip[16] = { 0 };
    memcpy(local_ip, src, family == AF_INET ? 4 : 16);

    /*
     * Wine allocates the socket inside wineserver and only then passes the fd to
     * the application, so immediately after connect() the sole holder can be
     * wineserver. Attributing the flow to wineserver would hide the real game
     * process from ExitLag, so retry briefly until a non-plumbing owner appears.
     * Bounded and cheap: the packet is already queued, and the loop gives up
     * quickly rather than delaying the verdict.
     */
    unsigned long inode = 0;
    char exe[256] = "";
    int linux_pid = 0;
    int wait_ms = 0;
    enum tcp_attribution_result attribution = TCP_ATTR_NONE;
    {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int attempt = 0; attempt < ATTR_MAX_ATTEMPTS; ++attempt) {
            if (!inode) {
                attribution = tcp_attribution_lookup(family, local_ip, ntohs(tcp->source),
                                                       dst, ntohs(tcp->dest), &inode);
                if (attribution == TCP_ATTR_INVALID || attribution == TCP_ATTR_AMBIGUOUS)
                    break;
            }
            if (inode) {
                linux_pid = pid_for_inode(inode, exe, sizeof(exe));
                if (linux_pid && !pid_is_wine_plumbing_num(linux_pid)) break;
            }
            struct timespec nap = { 0, ATTR_STEP_MS * 1000 * 1000 };
            nanosleep(&nap, NULL);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        wait_ms = (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
    }

    char from[96], to[96];
    format_endpoint(from, sizeof(from), family, src, tcp->source);
    format_endpoint(to, sizeof(to), family, dst, tcp->dest);

    struct process_identity owner = {0};
    if (attribution != TCP_ATTR_FOUND || !linux_pid ||
        !process_identity_read((pid_t)linux_pid, &owner) ||
        owner.uid != g_allowed_peer_uid || !process_identity_holds_socket(&owner, inode)) {
        log_line("tcp syn %s -> %s attribution=%d pid=%d inode=%lu | "
                 "unverified socket owner; callback skipped; ACCEPT (no new redirect)",
                 from, to, (int)attribution, linux_pid, inode);
        send_verdict(queue_num, packet_id, NF_ACCEPT);
        return MNL_CB_OK;
    }

    struct exl_tcp_connect_req req;
    memset(&req, 0, sizeof(req));
    req.tag = g_next_tag++;
    req.endpoint_id = g_next_endpoint++;
    req.process_id = (unsigned int)linux_pid;   /* real owning PID; the shim resolves its path */
    remember_observed_pid(req.process_id);
    req.filtering_flag = 0x10;             /* NF_INDICATE_CONNECT_REQUESTS */
    req.direction = 2;                     /* NF_D_OUT */
    req.ip_family = (unsigned short)(family == AF_INET ? 2 : 23);
    put_sockaddr(req.local_address, family, src, tcp->source);
    put_sockaddr(req.remote_address, family, dst, tcp->dest);

    /* Flow ordering/timing, so port-dependence can be told apart from
       order- or state-dependence when the same destination is probed twice. */
    struct timespec now_ts;
    clock_gettime(CLOCK_MONOTONIC, &now_ts);
    long long since_ms = -1;
    if (g_last_flow.tv_sec)
        since_ms = (now_ts.tv_sec - g_last_flow.tv_sec) * 1000LL +
                   (now_ts.tv_nsec - g_last_flow.tv_nsec) / 1000000LL;
    g_last_flow = now_ts;
    unsigned long long flow_index = ++g_flow_index;

    struct exl_tcp_connect_reply reply;
    memset(&reply, 0, sizeof(reply));
    int have_reply = (ask_shim_tcp_connect(&req, &reply) == 0);

    int redirect_armed = 0;
    int redirect_requested = 0;
    const char *redirect_failure = NULL;
    if (have_reply) {
        char after[96] = "";
        if (reply.mutated_remote) {
            int fam = reply.remote_address[0] == 23 ? AF_INET6 : AF_INET;
            unsigned short port_net;
            memcpy(&port_net, reply.remote_address + 2, 2);
            format_endpoint(after, sizeof(after), fam,
                            reply.remote_address + (fam == AF_INET ? 4 : 8), port_net);
        }

        /* Only a byte-real, callback-declared endpoint change is eligible.
           Padding-only sockaddr changes, wrong families and port zero all pass
           through unchanged. The same checks apply to both families; only the
           sockaddr layout and the "invalid target" set differ. */
        if (g_apply_tcp && (family == AF_INET || family == AF_INET6) &&
            reply.verdict == EXL_VERDICT_MUTATED && reply.mutated_remote) {
            const int v6 = (family == AF_INET6);
            /* sockaddr_in: family,port,addr@4. sockaddr_in6: family,port,flowinfo,addr@8. */
            const unsigned int addr_offset = v6 ? 8u : 4u;
            const size_t addr_len = v6 ? 16u : 4u;
            const unsigned short want_family = v6 ? 23u : 2u;   /* Windows AF_INET6 = 23 */
            const unsigned char *new_addr = reply.remote_address + addr_offset;
            unsigned short reply_family = (unsigned short)
                (reply.remote_address[0] | ((unsigned short)reply.remote_address[1] << 8));
            unsigned short new_port_net;
            memcpy(&new_port_net, reply.remote_address + 2, sizeof(new_port_net));
            int endpoint_changed = new_port_net != tcp->dest ||
                memcmp(new_addr, dst, addr_len) != 0;

            int invalid_target, non_loopback;
            if (v6) {
                struct in6_addr a6;
                memcpy(&a6, new_addr, sizeof(a6));
                /* :: is unspecified; ff00::/8 is multicast. */
                invalid_target = IN6_IS_ADDR_UNSPECIFIED(&a6) || IN6_IS_ADDR_MULTICAST(&a6);
                /* IPv6 equivalent of the 127/8 policy: ExitLag's proxy is ::1.
                   An IPv4-mapped loopback (::ffff:127.0.0.0/8) counts too, since
                   that is the same local proxy reached over a dual-stack socket. */
                non_loopback = !IN6_IS_ADDR_LOOPBACK(&a6) &&
                               !(IN6_IS_ADDR_V4MAPPED(&a6) && new_addr[12] == 127);
            } else {
                struct in_addr a4;
                memcpy(&a4, new_addr, sizeof(a4));
                invalid_target = a4.s_addr == htonl(INADDR_ANY) ||
                                 a4.s_addr == htonl(INADDR_BROADCAST) ||
                                 IN_MULTICAST(ntohl(a4.s_addr));
                non_loopback = (ntohl(a4.s_addr) >> 24) != 127;
            }

            if (reply_family != want_family)
                redirect_failure = v6 ? "callback returned non-IPv6 target for an IPv6 flow"
                                      : "callback returned non-IPv4 target";
            else if (!new_port_net) redirect_failure = "callback returned port zero";
            else if (invalid_target) redirect_failure = "callback returned invalid unicast target";
            else if (!endpoint_changed) redirect_failure = "callback changed only sockaddr metadata";
            else if (!g_allow_remote_redirect && non_loopback)
                redirect_failure = "callback returned a non-loopback target "
                                   "(refused: the proven runtime only redirects to ExitLag's local proxy; "
                                   "--allow-remote-redirect overrides)";
            else {
                unsigned long current_inode = 0;
                enum tcp_attribution_result current_attribution =
                    tcp_attribution_lookup(family, local_ip, ntohs(tcp->source),
                                           dst, ntohs(tcp->dest), &current_inode);
                if (current_attribution != TCP_ATTR_FOUND || current_inode != inode ||
                    !process_identity_holds_socket(&owner, inode)) {
                    redirect_failure = "socket owner exited, changed or released the flow during callback";
                } else {
                    redirect_requested = 1;
                    if (nft_arm_tcp_redirect(family, src, tcp->source, dst, tcp->dest,
                                         new_addr, new_port_net) == 0)
                        redirect_armed = 1;
                    else
                        redirect_failure = "nft map update failed";
                }
            }
        }

        log_line("flow=%llu dt_ms=%lld tag=%llu tcp syn %s -> %s dport=%u pid=%d exe=%s inode=%lu | "
                 "attr_wait=%dms verdict=%u flag=0x%x->0x%x ctrlflow=%s%s%s | %s",
                 flow_index, since_ms, (unsigned long long)req.tag, from, to,
                 (unsigned)ntohs(tcp->dest), linux_pid, exe[0] ? exe : "?", inode,
                 wait_ms, reply.verdict, req.filtering_flag, reply.filtering_flag,
                 ((reply.filtering_flag & 0x200) && !(req.filtering_flag & 0x200)) ? "added" : "no",
                 reply.mutated_remote ? " remote->" : "", reply.mutated_remote ? after : "",
                 redirect_armed ? "DNAT armed; ACCEPT (active)" :
                 (g_apply_tcp ? "ACCEPT unchanged (fail-open/no redirect)" : "ACCEPT unchanged (passive)"));
        if (redirect_failure)
            log_line("    redirect not armed: %s%s", redirect_failure,
                     redirect_requested ? "; no successful new redirect acknowledged" : "");
        if (g_last_candidates[0]) log_line("    holders: %s", g_last_candidates);
    } else {
        log_line("flow=%llu dt_ms=%lld tcp syn %s -> %s dport=%u pid=%d exe=%s | no shim reply | ACCEPT unchanged (fail-open)",
                 flow_index, since_ms, from, to, (unsigned)ntohs(tcp->dest), linux_pid, exe[0] ? exe : "?");
    }

    if (redirect_armed) {
        uint32_t authorized_priority = packet_priority | EXL_TCP_AUTH_PRIORITY;
        send_verdict_priority(queue_num, packet_id, NF_ACCEPT, &authorized_priority);
    } else {
        send_verdict(queue_num, packet_id, NF_ACCEPT);
    }
    return MNL_CB_OK;
}

static int nfq_config(int queue_num, unsigned short command, unsigned int range, unsigned char mode)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons((uint16_t)queue_num);
    if (command) {
        struct nfqnl_msg_config_cmd cmd = { 0 };
        cmd.command = (uint8_t)command;
        cmd.pf = htons(AF_INET);
        mnl_attr_put(nlh, NFQA_CFG_CMD, sizeof(cmd), &cmd);
    }
    if (mode) {
        struct nfqnl_msg_config_params params = { 0 };
        params.copy_range = htonl(range);
        params.copy_mode = mode;
        mnl_attr_put(nlh, NFQA_CFG_PARAMS, sizeof(params), &params);
    }
    return mnl_socket_sendto(g_nl, nlh, nlh->nlmsg_len) < 0 ? -1 : 0;
}

static int nfq_set_fail_open(int queue_num)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_UNSPEC; nfg->version = NFNETLINK_V0;
    nfg->res_id = htons((uint16_t)queue_num);
    mnl_attr_put_u32(nlh, NFQA_CFG_QUEUE_MAXLEN, htonl(4096));
#ifdef NFQA_CFG_F_FAIL_OPEN
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_FAIL_OPEN));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_FAIL_OPEN));
#endif
    return mnl_socket_sendto(g_nl, nlh, nlh->nlmsg_len) < 0 ? -1 : 0;
}

static int nfq_bind_one(int queue_num)
{
    return nfq_config(queue_num, NFQNL_CFG_CMD_BIND, 0, 0) == 0 &&
           nfq_config(queue_num, 0, 0xffff, NFQNL_COPY_PACKET) == 0 &&
           nfq_set_fail_open(queue_num) == 0 ? 0 : -1;
}


/*
 * Bring-up aid: synthesize one flow event (no packet involved) so the
 * Linux -> shim -> ExitLag -> shim -> Linux round trip can be proven before
 * any netfilter rule exists.
 */
static void run_self_test(const char *dest)
{
    char host[64]; unsigned int port = 80;
    snprintf(host, sizeof(host), "%s", dest);
    char *colon = strrchr(host, ':');
    if (colon) { *colon = 0; port = (unsigned int)strtoul(colon + 1, NULL, 10); }
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) != 1) { log_line("self-test: bad destination '%s'", dest); return; }

    struct in_addr local;
    inet_pton(AF_INET, "127.0.0.1", &local);

    struct exl_tcp_connect_req req;
    memset(&req, 0, sizeof(req));
    req.tag = g_next_tag++;
    req.endpoint_id = g_next_endpoint++;
    req.process_id = 0;
    req.filtering_flag = 0x10;
    req.direction = 2;
    req.ip_family = 2;
    put_sockaddr(req.local_address, AF_INET, &local, htons(54321));
    put_sockaddr(req.remote_address, AF_INET, &addr, htons((unsigned short)port));

    struct exl_tcp_connect_reply reply;
    memset(&reply, 0, sizeof(reply));
    if (ask_shim_tcp_connect(&req, &reply) != 0) { log_line("self-test: no reply from shim"); return; }
    log_line("self-test: dest=%s:%u verdict=%u flag=0x%x->0x%x mutated_flag=%u mutated_remote=%u",
             host, port, reply.verdict, req.filtering_flag, reply.filtering_flag,
             reply.mutated_flag, reply.mutated_remote);
}

int main(int argc, char **argv)
{
    unsigned short port = EXL_DEFAULT_PORT;
    const char *logpath = NULL;
    const char *identity_map_path = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--queue") && i + 1 < argc) g_queue_num = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = (unsigned short)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--log") && i + 1 < argc) logpath = argv[++i];
        else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc) {
            char *end = NULL;
            errno = 0;
            long value = strtol(argv[++i], &end, 10);
            if (errno || !argv[i][0] || !end || *end || value < 1 || value > 60000) {
                fprintf(stderr, "--timeout-ms must be an integer in 1..60000\n"); return 2;
            }
            g_reply_timeout_ms = (int)value;
        }
        else if (!strcmp(argv[i], "--no-queue")) g_no_queue = 1;
        else if (!strcmp(argv[i], "--peer-uid") && i + 1 < argc) g_allowed_peer_uid = (uid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--token-file") && i + 1 < argc) snprintf(g_token_path, sizeof(g_token_path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--allow-remote-redirect")) g_allow_remote_redirect = 1;
        else if (!strcmp(argv[i], "--allow-udp-remote-redirect")) g_allow_udp_remote = 1;
        else if (!strcmp(argv[i], "--allow-any-pid-resolve")) g_allow_any_pid_resolve = 1;
        else if (!strcmp(argv[i], "--apply-tcp")) g_apply_tcp = 1;
        else if (!strcmp(argv[i], "--apply-udp")) { g_apply_udp = 1; g_observe_udp = 1; }
        else if (!strcmp(argv[i], "--udp-active-once")) g_udp_active_once = 1;
        else if (!strcmp(argv[i], "--udp-multi")) g_udp_multi = 1;
        else if (!strcmp(argv[i], "--udp-active-index") && i + 1 < argc) {
            char *end = NULL;
            unsigned long value = strtoul(argv[++i], &end, 10);
            if (!argv[i][0] || !end || *end || value == 0 || value > UINT_MAX) {
                fprintf(stderr, "--udp-active-index must be a positive integer\n"); return 2;
            }
            g_udp_active_index = (unsigned int)value;
        }
        else if (!strcmp(argv[i], "--observe-udp")) g_observe_udp = 1;
        else if (!strcmp(argv[i], "--udp-queue") && i + 1 < argc) g_udp_queue_num = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--udp-exe") && i + 1 < argc) g_udp_exe = argv[++i];
        else if (!strcmp(argv[i], "--identity-map") && i + 1 < argc) identity_map_path = argv[++i];
        else if (!strcmp(argv[i], "--self-test") && i + 1 < argc) g_selftest = argv[++i];
        else { fprintf(stderr,
            "usage: %s [--queue N] [--port N] [--log FILE] [--timeout-ms N]\n"
            "          [--no-queue] [--apply-tcp] [--observe-udp|--apply-udp] [--udp-active-once]\n"
            "          [--udp-active-index N] [--udp-multi] [--allow-udp-remote-redirect]\n"
            "          [--udp-queue N] [--udp-exe TEXT] [--identity-map FILE]\n"
            "          [--self-test IPV4:PORT]\n"
            "  --no-queue   do not touch netfilter at all (validates the shim link only)\n"
            "  --peer-uid   uid permitted to connect besides root (default: $SUDO_UID)\n"
            "  --token-file where to publish this session's IPC token (0600, owner-only)\n"
            "  --allow-remote-redirect  permit non-loopback DNAT targets (default: refuse)\n"
            "  --allow-any-pid-resolve  resolve PIDs this helper never reported (test harnesses only)\n"
            "  --apply-tcp  apply valid IPv4/IPv6 address+port mutations via nftables DNAT\n"
            "  --observe-udp deliver UDP callbacks but always ACCEPT original packets\n"
            "  --apply-udp   execute only one live-proven post/rule form; all else ACCEPTs\n"
            "  --udp-active-once lock active UDP to one eligible endpoint id\n"
            "  --udp-multi  synchronous multi-endpoint IPv4/IPv6 post delivery (experimental)\n"
            "  --allow-udp-remote-redirect permit changed non-loopback UDP post destinations\n"
            "  --udp-active-index select the Nth eligible endpoint (1-based; default 1)\n"
            "  --udp-queue  NFQUEUE for both UDP directions (default: TCP queue + 1)\n"
            "  --udp-exe    accept queued UDP unchanged unless owner path contains TEXT\n"
            "  --identity-map native SOURCE<TAB>WINDOWS_PATH; prefix rows require <TAB>OWNER_EXE\n"
            "  --self-test  once the shim connects, synthesize one flow event to this\n"
            "               destination and report what ExitLag did with it\n", argv[0]); return 2; }
    }
    if (g_observe_udp && g_udp_queue_num < 0) g_udp_queue_num = g_queue_num + 1;
    if (g_observe_udp && g_udp_queue_num == g_queue_num) {
        fprintf(stderr, "TCP and UDP queue numbers must differ\n"); return 2;
    }
    if ((g_apply_udp && !g_udp_active_once && !g_udp_multi) ||
        (g_udp_multi && (!g_apply_udp || g_udp_active_once))) {
        fprintf(stderr, "--apply-udp requires exactly one of --udp-active-once or --udp-multi\n");
        return 2;
    }
    if (logpath) {
        g_log = private_log_open(logpath);
        if (!g_log) { perror("log"); return 1; }
        g_log_path = logpath;
        /* Overridable so rotation is testable without generating 8 MB. */
        const char *max = getenv("EXITLAG_LOG_MAX_BYTES");
        if (max && *max) {
            long v = strtol(max, NULL, 10);
            if (v > 0) g_log_max_bytes = v;
        }
    }

    /* Default the permitted peer to the desktop user who invoked sudo. Root is
       always permitted. If neither is knowable the helper still runs, but says
       so plainly -- a silent fallback here would mean an unauthenticated IPC
       socket owned by a root process. */
    if (g_allowed_peer_uid == (uid_t)-1) {
        /* Under sudo the desktop user is the one running ExitLag. Otherwise the
           owner is whoever started this helper: a helper running unprivileged
           can only usefully be driven by its own user, and defaulting to root
           there would lock out every non-root caller. */
        if (geteuid() != 0) {
            /* An unprivileged helper can only usefully be driven by its own
               user. SUDO_UID may be present and point somewhere else entirely
               (nested sudo rewrites it), so it is not consulted here. */
            g_allowed_peer_uid = getuid();
        } else {
            const char *sudo_uid = getenv("SUDO_UID");
            if (sudo_uid && *sudo_uid) g_allowed_peer_uid = (uid_t)strtoul(sudo_uid, NULL, 10);
            else g_allowed_peer_uid = getuid();
        }
    }
    log_line("IPC peer policy: uid 0 and uid %u may connect", (unsigned)g_allowed_peer_uid);

    if (!g_token_path[0]) {
        /* Root publishes under /run; an unprivileged helper (tests, IPC-only
           runs) uses the user's runtime dir, which only that user can read. */
        if (geteuid() == 0) {
            mkdir("/run/exitlag-linux", 0755);
            snprintf(g_token_path, sizeof(g_token_path), "/run/exitlag-linux/ipc.token");
        } else {
            const char *xdg = getenv("XDG_RUNTIME_DIR");
            if (xdg && *xdg) snprintf(g_token_path, sizeof(g_token_path), "%s/exitlag-ipc.token", xdg);
            else snprintf(g_token_path, sizeof(g_token_path), "/tmp/exitlag-ipc-%u.token", (unsigned)getuid());
        }
    }
    if (token_publish(g_allowed_peer_uid) != 0) {
        fprintf(stderr, "cannot publish the IPC session token; refusing to run unauthenticated\n");
        return 1;
    }
    atexit(token_remove);
    /*
     * A runner that forgets to pass --identity-map does not fail; it silently
     * runs without strict mode, so no identities are translated and Wine/Proton
     * processes retain only their kernel-reported host executable. This can
     * silently break intended routing. If the
     * environment asked for a map, refuse to run without it.
     */
    if (!identity_map_path) {
        const char *wanted = getenv("EXITLAG_IDENTITY_MAP");
        if (wanted && *wanted) {
            fprintf(stderr,
                    "EXITLAG_IDENTITY_MAP is set (%s) but --identity-map was not passed.\n"
                    "Refusing to start: this would run without strict identity matching,\n"
                    "silently leaving every process unmapped and unrouted.\n"
                    "The runner is responsible for forwarding it; see backend/runtime-guard.sh.\n",
                    wanted);
            return 2;
        }
    }
    if (identity_map_path && load_identity_map(identity_map_path) != 0) return 2;

    /* Endpoint ids must be unique across helper restarts: reusing them would let
       stale ExitLag per-endpoint state leak between experiments. */
    {
        unsigned long long seed = 0;
        ssize_t count;
        do { count = getrandom(&seed, sizeof(seed), 0); } while (count < 0 && errno == EINTR);
        if (count != sizeof(seed)) {
            log_line("cannot obtain a fresh endpoint generation; refusing startup"); return 1;
        }
        g_next_endpoint = seed | 0x100000000ULL;
        log_line("endpoint id base = 0x%llx", g_next_endpoint);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (bind(g_listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(g_listen_fd, 4) < 0) {
        log_line("cannot listen on 127.0.0.1:%u: %s", port, strerror(errno));
        return 1;
    }
    log_line("listening for shim on 127.0.0.1:%u", port);

    if (g_no_queue) {
        log_line("IPC-only mode: netfilter is untouched, no packets are observed");
    } else {
    g_nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!g_nl) { log_line("mnl_socket_open: %s (need CAP_NET_ADMIN)", strerror(errno)); return 1; }
    {
        int requested = 4 * 1024 * 1024;
        int configured = 0;
#ifdef SO_RCVBUFFORCE
        configured = setsockopt(mnl_socket_get_fd(g_nl), SOL_SOCKET, SO_RCVBUFFORCE,
                                &requested, sizeof(requested)) == 0;
#endif
        if (!configured &&
            setsockopt(mnl_socket_get_fd(g_nl), SOL_SOCKET, SO_RCVBUF,
                       &requested, sizeof(requested)) < 0)
            log_line("netlink receive-buffer request failed: %s", strerror(errno));
        int actual = 0;
        socklen_t actual_len = sizeof(actual);
        if (getsockopt(mnl_socket_get_fd(g_nl), SOL_SOCKET, SO_RCVBUF,
                       &actual, &actual_len) == 0)
            log_line("netlink receive buffer=%d bytes", actual);
    }
    if (mnl_socket_bind(g_nl, 0, MNL_SOCKET_AUTOPID) < 0) { log_line("mnl_socket_bind: %s", strerror(errno)); return 1; }
    g_portid = mnl_socket_get_portid(g_nl);

    if (nfq_bind_one(g_queue_num) < 0) {
        log_line("failed to bind NFQUEUE %d: %s", g_queue_num, strerror(errno));
        return 1;
    }
    log_line("bound NFQUEUE %d (%s)", g_queue_num,
             g_apply_tcp ? "active TCP redirect; all failures ACCEPT unchanged" :
                           "observation only; every packet ACCEPTed unchanged");
    if (g_observe_udp) {
        if (nfq_bind_one(g_udp_queue_num) < 0) {
            log_line("failed to bind UDP NFQUEUE %d: %s", g_udp_queue_num, strerror(errno));
            nfq_config(g_queue_num, NFQNL_CFG_CMD_UNBIND, 0, 0);
            return 1;
        }
        log_line("bound UDP NFQUEUE %d (%s; overflow fail-open)", g_udp_queue_num,
                 g_udp_multi ? "experimental multi-endpoint synchronous posts" :
                 g_apply_udp ? "active narrow post/reinject subset" :
                               "observation only; every datagram ACCEPTed unchanged");
    }
    }

    static unsigned char buf[EXL_MAX_PAYLOAD] __attribute__((aligned(8)));
    time_t last_heartbeat = 0;
    while (!g_stop) {
        struct pollfd pfds[3];
        int n = 0;
        int nl_index = -1;
        if (!g_no_queue) { nl_index = n; pfds[n].fd = mnl_socket_get_fd(g_nl); pfds[n].events = POLLIN; pfds[n].revents = 0; n++; }
        int listen_index = n;
        pfds[n].fd = g_listen_fd; pfds[n].events = POLLIN; pfds[n].revents = 0; n++;
        int shim_index = -1;
        int polled_shim_fd = g_shim_fd;
        uint64_t polled_session = g_udp_session;
        if (g_shim_fd >= 0) { shim_index = n; pfds[n].fd = g_shim_fd; pfds[n].events = POLLIN; pfds[n].revents = 0; n++; }

        int r = poll(pfds, (nfds_t)n, 1000);
        if (r < 0) { if (errno == EINTR) continue; break; }

        if (nl_index >= 0 && (pfds[nl_index].revents & POLLIN)) {
            ssize_t len = mnl_socket_recvfrom(g_nl, buf, sizeof(buf));
            if (len < 0) {
                if (errno == ENOBUFS) { log_line("kernel queue overrun (ENOBUFS); queue configured fail-open"); continue; }
                if (errno == EINTR) continue;
                log_line("recv error: %s", strerror(errno));
                break;
            }
            if (mnl_cb_run(buf, (size_t)len, 0, g_portid, on_packet, NULL) < 0)
                log_line("cb_run: %s", strerror(errno));
        }
        if (pfds[listen_index].revents & POLLIN) {
            int previous_shim_fd = g_shim_fd;
            accept_shim();
            if (g_selftest && g_shim_fd >= 0 && g_shim_fd != previous_shim_fd)
                run_self_test(g_selftest);
        }
        if (shim_index >= 0 && g_shim_fd == polled_shim_fd &&
            g_udp_session == polled_session && exl_ipc_ready(g_shim_fd) == 1 &&
            (pfds[shim_index].revents & (POLLIN | POLLHUP | POLLERR))) {
            /* The poll event belongs to the descriptor captured before accept;
               it must never be applied to a newly authenticated replacement,
               or reused after packet callbacks consumed that readiness. */
            struct exl_header head;
            static unsigned char tmp[EXL_MAX_PAYLOAD];
            exl_ipc_deadline deadline = exl_ipc_deadline_after(200);
            if (exl_ipc_recv_frame(g_shim_fd, &head, tmp, sizeof(tmp), deadline) != 0)
                drop_shim("unsolicited frame timeout, framing error or eof");
            else
                handle_nested_message(&head, tmp, deadline);
        }
        if (g_shim_fd >= 0) {
            struct timespec heartbeat_now;
            clock_gettime(CLOCK_MONOTONIC, &heartbeat_now);
            if (heartbeat_now.tv_sec - last_heartbeat >= 2) {
                if (send_frame(g_shim_fd, EXL_MSG_PING, NULL, 0) != 0)
                    drop_shim("heartbeat send failed");
                else
                    last_heartbeat = heartbeat_now.tv_sec;
            }
        } else {
            last_heartbeat = 0;
        }
        if (g_observe_udp) udp_reap_endpoints();
    }

    log_line("shutting down");
    if (!g_no_queue) {
        if (g_observe_udp) nfq_config(g_udp_queue_num, NFQNL_CFG_CMD_UNBIND, 0, 0);
        nfq_config(g_queue_num, NFQNL_CFG_CMD_UNBIND, 0, 0);
        mnl_socket_close(g_nl);
    }
    if (g_shim_fd >= 0) close(g_shim_fd);
    if (g_listen_fd >= 0) close(g_listen_fd);
    if (g_log) fclose(g_log);
    if (g_log_dir_fd >= 0) close(g_log_dir_fd);
    return 0;
}
