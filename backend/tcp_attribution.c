#define _POSIX_C_SOURCE 200809L
#include "tcp_attribution.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

struct tcp_tuple {
    int family;
    const unsigned char *local_ip;
    const unsigned char *remote_ip;
    unsigned short local_port;
    unsigned short remote_port;
};

static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_number(const char *text, size_t width, unsigned long *value)
{
    unsigned long result = 0;
    for (size_t i = 0; i < width; ++i) {
        int digit = hex_digit((unsigned char)text[i]);
        if (digit < 0 || result > (ULONG_MAX - (unsigned int)digit) / 16) return 0;
        result = result * 16 + (unsigned int)digit;
    }
    *value = result;
    return 1;
}

static int decimal_number(const char *text, unsigned long limit, unsigned long *value)
{
    unsigned long result = 0;
    if (!*text) return 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') return 0;
        unsigned int digit = (unsigned int)(*text - '0');
        if (result > (limit - digit) / 10) return 0;
        result = result * 10 + digit;
    }
    *value = result;
    return 1;
}

static int hex_pair(const char *text, size_t first_width, size_t second_width)
{
    unsigned long ignored;
    return strlen(text) == first_width + 1 + second_width &&
        text[first_width] == ':' && hex_number(text, first_width, &ignored) &&
        hex_number(text + first_width + 1, second_width, &ignored);
}

static int endpoint(const char *text, int family, unsigned char ip[16],
                    unsigned short *port)
{
    size_t bytes = family == AF_INET ? 4 : 16;
    size_t hexlen = bytes * 2;
    unsigned long number;
    if (strlen(text) != hexlen + 5 || text[hexlen] != ':' ||
        !hex_number(text + hexlen + 1, 4, &number)) return 0;
    *port = (unsigned short)number;
    /* On the supported Linux x86_64 target, /proc emits each address word
     * little-endian. Reverse bytes within EACH word, including IPv6 words. */
    for (size_t word = 0; word < bytes; word += 4) {
        for (size_t byte = 0; byte < 4; ++byte) {
            if (!hex_number(text + word * 2 + byte * 2, 2, &number)) return 0;
            ip[word + 3 - byte] = (unsigned char)number;
        }
    }
    return 1;
}

static char *token(char **cursor)
{
    char *start = *cursor;
    while (*start == ' ' || *start == '\t' || *start == '\n') ++start;
    if (!*start) { *cursor = start; return NULL; }
    char *end = start;
    while (*end && *end != ' ' && *end != '\t' && *end != '\n') ++end;
    if (*end) *end++ = '\0';
    *cursor = end;
    return start;
}

static int valid_header(char *line)
{
    static const char *const columns[] = {
        "sl", "local_address", NULL, "st", "tx_queue", "rx_queue", "tr",
        "tm->when", "retrnsmt", "uid", "timeout", "inode"
    };
    char *cursor = line;
    for (size_t i = 0; i < sizeof(columns) / sizeof(columns[0]); ++i) {
        char *part = token(&cursor);
        if (!part) return 0;
        if (i == 2) {
            if (strcmp(part, "rem_address") && strcmp(part, "remote_address")) return 0;
        } else if (strcmp(part, columns[i])) return 0;
    }
    return token(&cursor) == NULL;
}

/* Parse even nonmatching rows completely: a truncated or corrupt table cannot
 * establish that the chosen inode is the unique owner of this tuple. Kernel
 * fields after inode are diagnostics and are not part of socket identity. */
static int parse_row(char *line, const struct tcp_tuple *tuple, unsigned long *inode)
{
    char *parts[10], *cursor = line;
    unsigned long ignored, state, candidate;
    unsigned char local[16], remote[16];
    unsigned short local_port, remote_port;
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        parts[i] = token(&cursor);
        if (!parts[i]) return 0;
    }
    size_t slot_len = strlen(parts[0]);
    if (slot_len < 2 || parts[0][slot_len - 1] != ':') return 0;
    parts[0][slot_len - 1] = '\0';
    if (!decimal_number(parts[0], UINT_MAX, &ignored) ||
        !endpoint(parts[1], tuple->family, local, &local_port) ||
        !endpoint(parts[2], tuple->family, remote, &remote_port) ||
        strlen(parts[3]) != 2 || !hex_number(parts[3], 2, &state) ||
        state == 0 || state > 13 ||
        !hex_pair(parts[4], 8, 8) || !hex_pair(parts[5], 2, 8) ||
        strlen(parts[6]) != 8 || !hex_number(parts[6], 8, &ignored) ||
        !decimal_number(parts[7], UINT_MAX, &ignored) ||
        !decimal_number(parts[8], UINT_MAX, &ignored) ||
        !decimal_number(parts[9], ULONG_MAX, &candidate)) return 0;

    *inode = 0;
    if (!candidate || state == 0x0a || state == 0x06) return 1;
    size_t bytes = tuple->family == AF_INET ? 4 : 16;
    if (local_port == tuple->local_port && remote_port == tuple->remote_port &&
        !memcmp(local, tuple->local_ip, bytes) && !memcmp(remote, tuple->remote_ip, bytes))
        *inode = candidate;
    return 1;
}

static enum tcp_attribution_result scan_table(const char *path,
    const struct tcp_tuple *tuple, unsigned long *found)
{
    FILE *file = fopen(path, "r");
    if (!file) return TCP_ATTR_INVALID;
    enum tcp_attribution_result result = TCP_ATTR_NONE;
    char line[1024];
    if (!fgets(line, sizeof(line), file) || !strchr(line, '\n') || !valid_header(line)) {
        result = TCP_ATTR_INVALID;
        goto done;
    }
    while (fgets(line, sizeof(line), file)) {
        unsigned long inode;
        if (!strchr(line, '\n') || !parse_row(line, tuple, &inode)) {
            result = TCP_ATTR_INVALID;
            goto done;
        }
        if (!inode) continue;
        if (*found && *found != inode) {
            result = TCP_ATTR_AMBIGUOUS;
            goto done;
        }
        *found = inode;
    }
    if (ferror(file)) result = TCP_ATTR_INVALID;
done:
    if (fclose(file) != 0) result = TCP_ATTR_INVALID;
    return result;
}

enum tcp_attribution_result tcp_attribution_lookup_files(
    const char *tcp_path, const char *tcp6_path, int family,
    const unsigned char *local_ip, unsigned short local_port,
    const unsigned char *remote_ip, unsigned short remote_port,
    unsigned long *inode_out)
{
    if (!inode_out) return TCP_ATTR_INVALID;
    *inode_out = 0;
    if (!local_ip || !remote_ip || (family != AF_INET && family != AF_INET6) ||
        !tcp6_path || (family == AF_INET && !tcp_path)) return TCP_ATTR_INVALID;
    /* /proc has no interface scope. Equal link-local addresses on distinct
     * interfaces cannot prove which socket owns the queued packet. */
    if (family == AF_INET6 &&
        ((local_ip[0] == 0xfe && (local_ip[1] & 0xc0) == 0x80) ||
         (remote_ip[0] == 0xfe && (remote_ip[1] & 0xc0) == 0x80))) return TCP_ATTR_INVALID;
    unsigned long found = 0;
    struct tcp_tuple tuple = { family, local_ip, remote_ip, local_port, remote_port };
    if (family == AF_INET) {
        enum tcp_attribution_result result = scan_table(tcp_path, &tuple, &found);
        if (result < 0) return result;
        unsigned char local_mapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        unsigned char remote_mapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
        memcpy(local_mapped + 12, local_ip, 4);
        memcpy(remote_mapped + 12, remote_ip, 4);
        tuple = (struct tcp_tuple){ AF_INET6, local_mapped, remote_mapped,
                                   local_port, remote_port };
        result = scan_table(tcp6_path, &tuple, &found);
        if (result < 0) return result;
    } else {
        enum tcp_attribution_result result = scan_table(tcp6_path, &tuple, &found);
        if (result < 0) return result;
    }
    *inode_out = found;
    return found ? TCP_ATTR_FOUND : TCP_ATTR_NONE;
}

enum tcp_attribution_result tcp_attribution_lookup(
    int family, const unsigned char *local_ip, unsigned short local_port,
    const unsigned char *remote_ip, unsigned short remote_port,
    unsigned long *inode_out)
{
    return tcp_attribution_lookup_files("/proc/net/tcp", "/proc/net/tcp6", family,
        local_ip, local_port, remote_ip, remote_port, inode_out);
}
