#define _POSIX_C_SOURCE 200809L
#include "../backend/process_identity.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t stat_fixture(char *buffer, size_t capacity, const char *pid,
                           const char *comm, unsigned int changed_field,
                           const char *changed_value, unsigned int last_field)
{
    int count = snprintf(buffer, capacity, "%s (%s) S", pid, comm);
    assert(count > 0 && (size_t)count < capacity);
    size_t used = (size_t)count;
    for (unsigned int field = 4; field <= last_field; ++field) {
        const char *value = "0";
        if (field == 8) value = "-1";
        if (field == 16) value = "-10";
        if (field == 18) value = "20";
        if (field == 19) value = "-5";
        if (field == 20) value = "1";
        if (field == 22) value = "123456";
        if (field == 25) value = "18446744073709551615";
        if (field == changed_field) value = changed_value;
        count = snprintf(buffer + used, capacity - used, " %s", value);
        assert(count > 0 && (size_t)count < capacity - used);
        used += (size_t)count;
    }
    assert(used + 2 <= capacity);
    buffer[used++] = '\n';
    buffer[used] = '\0';
    return used;
}

static void expect_stat(const char *text, size_t length, int expected,
                         unsigned long long birth)
{
    unsigned long long value = 999;
    assert(process_identity_parse_stat(text, length, 42, &value) == expected);
    assert(value == birth);
}

static void stat_parser(void)
{
    char buffer[4096];
    size_t length = stat_fixture(buffer, sizeof(buffer), "42", "a ) name\n(", 0, NULL, 52);
    expect_stat(buffer, length, 1, 123456);
    length = stat_fixture(buffer, sizeof(buffer), "42", "", 22, "0", 52);
    expect_stat(buffer, length, 1, 0);
    length = stat_fixture(buffer, sizeof(buffer), "42", "paren (() )", 22,
                           "18446744073709551615", 52);
    expect_stat(buffer, length, 1, ULLONG_MAX);
    length = stat_fixture(buffer, sizeof(buffer), "42", "signed limits", 16,
                           "-9223372036854775808", 52);
    expect_stat(buffer, length, 1, 123456);
    length = stat_fixture(buffer, sizeof(buffer), "42", "int limit", 8, "-2147483648", 52);
    expect_stat(buffer, length, 1, 123456);
    static const struct { unsigned int field; const char *value; } invalid_fields[] = {
        {4, "+1"}, {4, "2147483648"}, {8, "-2147483649"}, {9, "4294967296"},
        {10, "-1"}, {16, "-9223372036854775809"}, {16, "+1"}, {16, "--1"},
        {16, "9223372036854775808"}, {22, "-1"}, {22, "+1"},
        {22, "18446744073709551616"}, {22, "123x"}, {22, ""},
        {40, "4294967296"}, {41, "-1"}, {52, "2147483648"}, {52, "0suffix"}
    };
    for (size_t i = 0; i < sizeof(invalid_fields) / sizeof(invalid_fields[0]); ++i) {
        length = stat_fixture(buffer, sizeof(buffer), "42", "valid name",
            invalid_fields[i].field, invalid_fields[i].value, 52);
        expect_stat(buffer, length, 0, 0);
    }
    static const char *const invalid_pids[] = { "0", "41", "+42", "-42", "2147483648", "42x" };
    for (size_t i = 0; i < sizeof(invalid_pids) / sizeof(invalid_pids[0]); ++i) {
        length = stat_fixture(buffer, sizeof(buffer), invalid_pids[i], "name", 0, NULL, 52);
        expect_stat(buffer, length, 0, 0);
    }
    length = stat_fixture(buffer, sizeof(buffer), "42", "name", 0, NULL, 21);
    expect_stat(buffer, length, 0, 0);
    length = stat_fixture(buffer, sizeof(buffer), "42", "name", 0, NULL, 51);
    expect_stat(buffer, length, 0, 0);
    length = stat_fixture(buffer, sizeof(buffer), "42", "name", 0, NULL, 53);
    expect_stat(buffer, length, 0, 0);
    length = stat_fixture(buffer, sizeof(buffer), "42", "name", 0, NULL, 52);
    expect_stat(buffer, length - 1, 0, 0);
    char *close = strchr(buffer, ')'); assert(close);
    close[2] = '?';
    expect_stat(buffer, length, 0, 0);
    close[2] = 'S'; close[0] = '(';
    expect_stat(buffer, length, 0, 0);
    length = stat_fixture(buffer, sizeof(buffer), "42", "name", 0, NULL, 52);
    buffer[4] = '\0';
    expect_stat(buffer, length, 0, 0);
    unsigned long long value = 123;
    assert(!process_identity_parse_stat(NULL, 0, 42, &value) && value == 0);
    assert(!process_identity_parse_stat(buffer, length, 42, NULL));
}

static void expect_status(const char *text, size_t length, uid_t owner, int expected)
{
    uid_t uid = 999;
    assert(process_identity_parse_status(text, length, 42, owner, &uid) == expected);
    assert(uid == (expected ? owner : 0));
}

static void status_parser(void)
{
    static const char good[] = "Name:\ta ) name (\nState:\tS (sleeping)\nPid:\t42\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
    expect_status(good, sizeof(good) - 1, 1000, 1);
    expect_status(good, sizeof(good) - 1, 0, 0);
    static const char max_uid[] = "Uid:\t4294967295 4294967295 4294967295 4294967295\nPid: 42\n";
    expect_status(max_uid, sizeof(max_uid) - 1, (uid_t)-1, 1);
    static const char *const bad_uids[] = {
        "999 1000 1000 1000", "1000 999 1000 1000", "1000 1000 999 1000",
        "1000 1000 1000 999", "1000 1000 1000", "1000 1000 1000 1000 1000",
        "+1000 1000 1000 1000", "-1 1000 1000 1000", "1000x 1000 1000 1000",
        "4294967296 1000 1000 1000", "", "1000\r 1000 1000 1000"
    };
    char buffer[512];
    for (size_t i = 0; i < sizeof(bad_uids) / sizeof(bad_uids[0]); ++i) {
        int count = snprintf(buffer, sizeof(buffer), "Pid:\t42\nUid:\t%s\n", bad_uids[i]);
        assert(count > 0 && (size_t)count < sizeof(buffer));
        expect_status(buffer, (size_t)count, 1000, 0);
    }
    static const char *const malformed[] = {
        "Uid: 1000 1000 1000 1000\n",
        "Pid: 42\n",
        "Pid: 41\nUid: 1000 1000 1000 1000\n",
        "Pid: +42\nUid: 1000 1000 1000 1000\n",
        "Pid: 2147483648\nUid: 1000 1000 1000 1000\n",
        "Pid: 42x\nUid: 1000 1000 1000 1000\n",
        "Pid: 42 43\nUid: 1000 1000 1000 1000\n",
        "Pid: 42\nPid: 42\nUid: 1000 1000 1000 1000\n",
        "Pid: 42\nUid: 1000 1000 1000 1000\nUid: 1000 1000 1000 1000\n",
        "Pid:42\nUid: 1000 1000 1000 1000\n",
        "Pid: 42\nUid:1000 1000 1000 1000\n"
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i)
        expect_status(malformed[i], strlen(malformed[i]), 1000, 0);
    expect_status(good, sizeof(good) - 2, 1000, 0);
    memcpy(buffer, good, sizeof(good)); buffer[2] = '\0';
    expect_status(buffer, sizeof(good) - 1, 1000, 0);
    uid_t uid = 999;
    assert(!process_identity_parse_status(NULL, 0, 42, 1000, &uid) && uid == 0);
    assert(!process_identity_parse_status(good, sizeof(good) - 1, 42, 1000, NULL));
}

static unsigned long inode_for(int fd)
{
    struct stat metadata;
    assert(fstat(fd, &metadata) == 0);
    assert(S_ISSOCK(metadata.st_mode));
    return (unsigned long)metadata.st_ino;
}

static void live_self(void)
{
    struct process_identity identity;
    assert(process_identity_read(getpid(), &identity));
    assert(identity.pid == getpid() && identity.uid == geteuid());
    /* An unrelated long pathname is normal (not a malformed socket link).
     * Open it first so fd enumeration encounters it before the socket. */
    char directory[] = "/tmp/exl-process-identity-XXXXXX";
    assert(mkdtemp(directory));
    char long_path[256];
    int prefix = snprintf(long_path, sizeof(long_path), "%s/", directory);
    assert(prefix > 0 && prefix < 64);
    memset(long_path + prefix, 'x', 160);
    long_path[prefix + 160] = '\0';
    FILE *long_file = fopen(long_path, "w+"); assert(long_file);
    assert(unlink(long_path) == 0 && rmdir(directory) == 0);
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0); assert(socket_fd >= 0);
    unsigned long inode = inode_for(socket_fd);
    assert(process_identity_holds_socket(&identity, inode));
    assert(!process_identity_holds_socket(&identity, ULONG_MAX));
    assert(!process_identity_holds_socket(&identity, 0));
    assert(!process_identity_holds_socket(NULL, inode));
    struct process_identity changed = identity;
    ++changed.start_time;
    assert(!process_identity_holds_socket(&changed, inode));
    changed = identity; changed.uid ^= 1;
    assert(!process_identity_holds_socket(&changed, inode));
    changed = identity; changed.pid = 0;
    assert(!process_identity_holds_socket(&changed, inode));
    char old_name[16];
    assert(prctl(PR_GET_NAME, old_name, 0, 0, 0) == 0);
    assert(prctl(PR_SET_NAME, "a ) name\n(", 0, 0, 0) == 0);
    struct process_identity renamed;
    assert(process_identity_read(getpid(), &renamed));
    assert(renamed.start_time == identity.start_time && renamed.uid == identity.uid);
    assert(process_identity_holds_socket(&identity, inode));
    assert(prctl(PR_SET_NAME, old_name, 0, 0, 0) == 0);
    int duplicate = dup(socket_fd); assert(duplicate >= 0);
    assert(close(socket_fd) == 0);
    assert(process_identity_holds_socket(&identity, inode));
    assert(close(duplicate) == 0);
    assert(!process_identity_holds_socket(&identity, inode));
    FILE *ordinary_file = tmpfile(); assert(ordinary_file);
    struct stat metadata;
    assert(fstat(fileno(ordinary_file), &metadata) == 0);
    assert(!process_identity_holds_socket(&identity, (unsigned long)metadata.st_ino));
    assert(fclose(ordinary_file) == 0);
    assert(fclose(long_file) == 0);
    memset(&changed, 0xff, sizeof(changed));
    assert(!process_identity_read(0, &changed));
    assert(changed.pid == 0 && changed.uid == 0 && changed.start_time == 0);
    assert(!process_identity_read(getpid(), NULL));
}

static void live_child(void)
{
    int commands[2], events[2];
    assert(pipe(commands) == 0 && pipe(events) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(commands[1]); close(events[0]);
        int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        assert(socket_fd >= 0);
        unsigned long inode = inode_for(socket_fd);
        assert(write(events[1], &inode, sizeof(inode)) == sizeof(inode));
        char command;
        assert(read(commands[0], &command, 1) == 1 && command == 'c');
        assert(close(socket_fd) == 0);
        assert(write(events[1], "c", 1) == 1);
        assert(read(commands[0], &command, 1) == 1 && command == 'e');
        close(commands[0]); close(events[1]);
        _exit(0);
    }
    close(commands[0]); close(events[1]);
    unsigned long inode;
    assert(read(events[0], &inode, sizeof(inode)) == sizeof(inode));
    struct process_identity identity, self, after;
    assert(process_identity_read(child, &identity));
    assert(identity.pid == child);
    assert(process_identity_holds_socket(&identity, inode));
    assert(process_identity_read(getpid(), &self));
    assert(!process_identity_holds_socket(&self, inode));
    assert(write(commands[1], "c", 1) == 1);
    char event;
    assert(read(events[0], &event, 1) == 1 && event == 'c');
    assert(process_identity_read(child, &after));
    assert(identity.start_time == after.start_time && identity.uid == after.uid);
    assert(!process_identity_holds_socket(&identity, inode));
    assert(write(commands[1], "e", 1) == 1);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!process_identity_holds_socket(&identity, inode));
    memset(&after, 0xff, sizeof(after));
    assert(!process_identity_read(child, &after));
    assert(after.pid == 0 && after.uid == 0 && after.start_time == 0);
    close(commands[1]); close(events[0]);
}

int main(void)
{
    stat_parser();
    status_parser();
    live_self();
    live_child();
    puts("PASS: process stat/status parsing, kernel PID generation/UID, live socket ownership, close and exit");
    return 0;
}
