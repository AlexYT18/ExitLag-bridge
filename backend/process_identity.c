#define _POSIX_C_SOURCE 200809L
#include "process_identity.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int unsigned_number(const char *begin, const char *end,
                            unsigned long long limit, unsigned long long *out)
{
    unsigned long long value = 0;
    if (begin == end) return 0;
    for (; begin < end; ++begin) {
        if (*begin < '0' || *begin > '9') return 0;
        unsigned int digit = (unsigned int)(*begin - '0');
        if (value > (limit - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    *out = value;
    return 1;
}

static int signed_field(unsigned int field)
{
    return (field >= 4 && field <= 8) || (field >= 16 && field <= 21) ||
        field == 24 || field == 38 || field == 39 || field == 44 || field == 52;
}

int process_identity_parse_stat(const char *text, size_t length, pid_t expected_pid,
                                unsigned long long *start_time)
{
    if (!start_time) return 0;
    *start_time = 0;
    if (!text || !length || expected_pid <= 0 || text[length - 1] != '\n' ||
        memchr(text, '\0', length)) return 0;
    const char *end = text + length - 1;
    const char *space = memchr(text, ' ', (size_t)(end - text));
    unsigned long long number;
    if (!space || space + 1 >= end || space[1] != '(' ||
        !unsigned_number(text, space, INT_MAX, &number) || number != (unsigned int)expected_pid)
        return 0;
    const char *close = end;
    while (close > space + 1 && *close != ')') --close;
    if (close <= space + 1 || end - close < 4 || close[1] != ' ' ||
        !strchr("RSDTtXZxKWPI", close[2]) || close[3] != ' ') return 0;

    const char *cursor = close + 4;
    unsigned long long birth = 0;
    for (unsigned int field = 4; field <= 52; ++field) {
        while (cursor < end && *cursor == ' ') ++cursor;
        const char *part = cursor;
        while (cursor < end && *cursor != ' ') ++cursor;
        unsigned long long limit = ULLONG_MAX;
        if (signed_field(field)) {
            limit = field <= 8 || field == 38 || field == 39 || field == 52 ? INT_MAX : LLONG_MAX;
            if (part < cursor && *part == '-') { ++part; ++limit; }
        } else if (field == 9 || field == 40 || field == 41) limit = UINT_MAX;
        if (!unsigned_number(part, cursor, limit, &number)) return 0;
        if (field == 22) birth = number;
    }
    /* The supported Linux stat record has 52 fields. Reject truncated records
     * and unknown suffixes rather than infer identity from a partial read. */
    if (cursor != end) return 0;
    *start_time = birth;
    return 1;
}

static int status_numbers(const char *begin, const char *end, size_t count,
                           unsigned long long limit, unsigned long long *values)
{
    for (size_t i = 0; i < count; ++i) {
        const char *previous = begin;
        while (begin < end && (*begin == ' ' || *begin == '\t')) ++begin;
        if (begin == previous) return 0;
        const char *number = begin;
        while (begin < end && *begin != ' ' && *begin != '\t') ++begin;
        if (!unsigned_number(number, begin, limit, &values[i])) return 0;
    }
    while (begin < end && (*begin == ' ' || *begin == '\t')) ++begin;
    return begin == end;
}

int process_identity_parse_status(const char *text, size_t length, pid_t expected_pid,
                                  uid_t proc_owner, uid_t *uid)
{
    if (!uid) return 0;
    *uid = 0;
    if (!text || !length || expected_pid <= 0 || text[length - 1] != '\n' ||
        memchr(text, '\0', length)) return 0;
    const char *cursor = text, *end = text + length;
    int have_pid = 0, have_uid = 0;
    while (cursor < end) {
        const char *newline = memchr(cursor, '\n', (size_t)(end - cursor));
        if (!newline) return 0;
        if (newline - cursor >= 4 && !memcmp(cursor, "Pid:", 4)) {
            unsigned long long value;
            if (have_pid || !status_numbers(cursor + 4, newline, 1, INT_MAX, &value) ||
                value != (unsigned int)expected_pid) return 0;
            have_pid = 1;
        } else if (newline - cursor >= 4 && !memcmp(cursor, "Uid:", 4)) {
            unsigned long long values[4];
            if (have_uid || !status_numbers(cursor + 4, newline, 4, (uid_t)-1, values)) return 0;
            for (size_t i = 0; i < 4; ++i) if (values[i] != proc_owner) return 0;
            have_uid = 1;
        }
        cursor = newline + 1;
    }
    if (!have_pid || !have_uid) return 0;
    *uid = proc_owner;
    return 1;
}

static int read_at(int proc_fd, const char *name, char *buffer, size_t capacity,
                    size_t *length)
{
    int fd = openat(proc_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    size_t used = 0;
    int ok = 0;
    while (used < capacity) {
        ssize_t count = read(fd, buffer + used, capacity - used);
        if (count < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (!count) { ok = 1; break; }
        used += (size_t)count;
    }
    if (close(fd) != 0) ok = 0;
    *length = used;
    return ok;
}

static int read_identity_at(int proc_fd, pid_t pid, struct process_identity *identity)
{
    char stat_text[4096], status_text[16384];
    size_t stat_length, status_length;
    struct stat directory, after;
    if (fstat(proc_fd, &directory) != 0 || !S_ISDIR(directory.st_mode) ||
        !read_at(proc_fd, "stat", stat_text, sizeof(stat_text), &stat_length) ||
        !read_at(proc_fd, "status", status_text, sizeof(status_text), &status_length) ||
        !process_identity_parse_stat(stat_text, stat_length, pid, &identity->start_time) ||
        !process_identity_parse_status(status_text, status_length, pid, directory.st_uid,
                                        &identity->uid) ||
        fstat(proc_fd, &after) != 0 || after.st_uid != directory.st_uid) return 0;
    identity->pid = pid;
    return 1;
}

static int same_identity(const struct process_identity *left,
                          const struct process_identity *right)
{
    return left->pid == right->pid && left->uid == right->uid &&
        left->start_time == right->start_time;
}

static int open_process(pid_t pid)
{
    if (pid <= 0) return -1;
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/%ld", (long)pid);
    if (length < 0 || (size_t)length >= sizeof(path)) return -1;
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

int process_identity_read(pid_t pid, struct process_identity *identity)
{
    if (!identity) return 0;
    memset(identity, 0, sizeof(*identity));
    int proc_fd = open_process(pid);
    if (proc_fd < 0) return 0;
    struct process_identity first, second;
    int ok = read_identity_at(proc_fd, pid, &first) &&
        read_identity_at(proc_fd, pid, &second) && same_identity(&first, &second);
    if (close(proc_fd) != 0) ok = 0;
    if (ok) *identity = first;
    return ok;
}

static int socket_fd_at(int proc_fd, unsigned long inode)
{
    int fd = openat(proc_fd, "fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    DIR *fds = fdopendir(fd);
    if (!fds) { close(fd); return 0; }
    char wanted[64];
    int wanted_length = snprintf(wanted, sizeof(wanted), "socket:[%lu]", inode);
    int found = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(fds);
        if (!entry) { if (errno) found = 0; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        unsigned long long number;
        if (!unsigned_number(entry->d_name, entry->d_name + strlen(entry->d_name),
                              INT_MAX, &number)) { found = 0; break; }
        char target[128];
        ssize_t length = readlinkat(dirfd(fds), entry->d_name, target, sizeof(target));
        if (length < 0) { found = 0; break; }
        /* A long unrelated pathname may be truncated; it cannot equal the
         * complete, shorter socket:[inode] target. */
        if (length == wanted_length && !memcmp(target, wanted, (size_t)length)) {
            found = 1;
            break;
        }
    }
    if (closedir(fds) != 0) found = 0;
    return found;
}

int process_identity_holds_socket(const struct process_identity *identity,
                                  unsigned long inode)
{
    if (!identity || identity->pid <= 0 || !inode) return 0;
    int proc_fd = open_process(identity->pid);
    if (proc_fd < 0) return 0;
    struct process_identity before, after;
    int ok = read_identity_at(proc_fd, identity->pid, &before) &&
        same_identity(identity, &before) && socket_fd_at(proc_fd, inode) &&
        read_identity_at(proc_fd, identity->pid, &after) && same_identity(identity, &after);
    if (close(proc_fd) != 0) ok = 0;
    return ok;
}
