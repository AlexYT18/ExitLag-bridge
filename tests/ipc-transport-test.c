#define _POSIX_C_SOURCE 200809L
#include "../backend/ipc_transport.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void pair(int fd[2]) { assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0); }
static void pause_ms(long ms)
{
    struct timespec ts = { ms / 1000, ms % 1000 * 1000000 };
    while (nanosleep(&ts, &ts) && errno == EINTR) {}
}
static void reap(pid_t child)
{
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void roundtrip(void)
{
    int fd[2]; pair(fd);
    struct exl_header head;
    char data[8] = { 0 };
    exl_ipc_deadline deadline = exl_ipc_deadline_after(500);
    assert(exl_ipc_send_frame(fd[0], EXL_MSG_LOG, "hello", 5, deadline) == 0);
    assert(exl_ipc_recv_frame(fd[1], &head, data, sizeof(data), deadline) == 0);
    assert(head.type == EXL_MSG_LOG && head.flags == 0 && head.length == 5);
    assert(!memcmp(data, "hello", 5));
    assert(exl_ipc_send_frame(fd[0], EXL_MSG_PING, NULL, 0, deadline) == 0);
    assert(exl_ipc_recv_frame(fd[1], &head, NULL, 0, deadline) == 0);
    assert(head.length == 0);
    close(fd[0]); close(fd[1]);
}

static void reject_header(unsigned int magic, unsigned short flags, unsigned int length,
                          size_t capacity, int expected_errno)
{
    int fd[2]; pair(fd);
    struct exl_header head = { magic, EXL_MSG_LOG, flags, length }, received;
    char buffer[8];
    exl_ipc_deadline deadline = exl_ipc_deadline_after(500);
    assert(exl_ipc_write_exact(fd[0], &head, sizeof(head), deadline) == 0);
    assert(exl_ipc_recv_frame(fd[1], &received, buffer, capacity, deadline) == -1);
    assert(errno == expected_errno);
    close(fd[0]); close(fd[1]);
}

static void fragmented_frame(void)
{
    int fd[2]; pair(fd);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(fd[0]);
        struct exl_header header = { EXL_MAGIC, EXL_MSG_LOG, 0, 3 };
        unsigned char frame[sizeof(header) + 3];
        memcpy(frame, &header, sizeof(header));
        memcpy(frame + sizeof(header), "abc", 3);
        for (size_t i = 0; i < sizeof(frame); ++i) {
            if (send(fd[1], frame + i, 1, MSG_NOSIGNAL) != 1) _exit(1);
            pause_ms(1);
        }
        close(fd[1]); _exit(0);
    }
    close(fd[1]);
    struct exl_header header; char payload[3];
    assert(exl_ipc_recv_frame(fd[0], &header, payload, sizeof(payload),
                             exl_ipc_deadline_after(1000)) == 0);
    assert(!memcmp(payload, "abc", sizeof(payload)));
    close(fd[0]); reap(child);
}

static void byte_dribble_deadline(void)
{
    int fd[2]; pair(fd);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(fd[0]);
        for (unsigned int i = 0; i < 8; ++i) {
            if (send(fd[1], "x", 1, MSG_NOSIGNAL) != 1) break;
            pause_ms(20);
        }
        close(fd[1]); _exit(0);
    }
    close(fd[1]); char bytes[8];
    exl_ipc_deadline deadline = exl_ipc_deadline_after(60);
    assert(exl_ipc_read_exact(fd[0], bytes, sizeof(bytes), deadline) == -1);
    assert(errno == ETIMEDOUT);
    close(fd[0]); reap(child);
}

static void header_body_share_deadline(void)
{
    int fd[2]; pair(fd);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(fd[0]);
        struct exl_header header = { EXL_MAGIC, EXL_MSG_LOG, 0, 1 };
        pause_ms(50);
        if (send(fd[1], &header, sizeof(header), MSG_NOSIGNAL) == sizeof(header)) {
            pause_ms(70);
            (void)send(fd[1], "x", 1, MSG_NOSIGNAL);
        }
        close(fd[1]); _exit(0);
    }
    close(fd[1]); struct exl_header header; char payload;
    assert(exl_ipc_recv_frame(fd[0], &header, &payload, 1,
                             exl_ipc_deadline_after(90)) == -1);
    assert(errno == ETIMEDOUT);
    close(fd[0]); reap(child);
}

static void blocked_writer(void)
{
    int fd[2]; pair(fd);
    int small = 1024;
    assert(setsockopt(fd[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    size_t length = 1024 * 1024;
    unsigned char *bytes = calloc(1, length); assert(bytes);
    assert(exl_ipc_write_exact(fd[0], bytes, length,
                              exl_ipc_deadline_after(40)) == -1);
    assert(errno == ETIMEDOUT);
    free(bytes); close(fd[0]); close(fd[1]);
}

static volatile sig_atomic_t interrupted;
static void alarm_handler(int sig) { (void)sig; interrupted = 1; }

static void interrupted_reader(void)
{
    int fd[2]; pair(fd);
    struct sigaction action = { 0 };
    action.sa_handler = alarm_handler;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGUSR1, &action, NULL) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(fd[0]); pause_ms(20); kill(getppid(), SIGUSR1); pause_ms(20);
        if (send(fd[1], "y", 1, MSG_NOSIGNAL) != 1) _exit(1);
        close(fd[1]); _exit(0);
    }
    close(fd[1]); char byte;
    assert(exl_ipc_read_exact(fd[0], &byte, 1, exl_ipc_deadline_after(500)) == 0);
    assert(byte == 'y' && interrupted);
    close(fd[0]); reap(child);
}

static void disconnect_and_limits(void)
{
    int fd[2]; pair(fd); close(fd[1]);
    char byte;
    assert(exl_ipc_read_exact(fd[0], &byte, 1, exl_ipc_deadline_after(100)) == -1);
    assert(errno == ECONNRESET);
    assert(exl_ipc_write_exact(fd[0], "x", 1, exl_ipc_deadline_after(100)) == -1);
    assert(errno == EPIPE);
    assert(exl_ipc_send_frame(fd[0], EXL_MSG_LOG, "x", EXL_MAX_PAYLOAD + 1,
                              exl_ipc_deadline_after(100)) == -1);
    assert(errno == EMSGSIZE);
    assert(exl_ipc_deadline_after(0) == -1 && errno == EINVAL);
    assert(exl_ipc_deadline_after(-1) == -1 && errno == EINVAL);
    close(fd[0]);
}

static void consumed_readiness(void)
{
    int fd[2]; pair(fd);
    assert(exl_ipc_ready(fd[1]) == 0);
    assert(exl_ipc_send_frame(fd[0], EXL_MSG_PONG, NULL, 0, exl_ipc_deadline_after(100)) == 0);
    assert(exl_ipc_ready(fd[1]) == 1);
    struct exl_header header; unsigned char payload[1];
    assert(exl_ipc_recv_frame(fd[1], &header, payload, sizeof(payload), exl_ipc_deadline_after(100)) == 0);
    assert(header.type == EXL_MSG_PONG);
    assert(exl_ipc_ready(fd[1]) == 0); /* Old poll result must not trigger another read. */
    close(fd[0]);
    assert(exl_ipc_ready(fd[1]) == 1); /* Real EOF remains observable. */
    close(fd[1]);
    assert(exl_ipc_ready(fd[1]) == -1 && errno == EBADF);
    assert(exl_ipc_ready(-1) == -1 && errno == EBADF);
}

int main(void)
{
    roundtrip();
    reject_header(0, 0, 0, 8, EPROTO);
    reject_header(EXL_MAGIC, 1, 0, 8, EPROTO);
    reject_header(EXL_MAGIC, 0, EXL_MAX_PAYLOAD + 1, 8, EPROTO);
    reject_header(EXL_MAGIC, 0, 9, 8, EMSGSIZE);
    fragmented_frame();
    byte_dribble_deadline();
    header_body_share_deadline();
    blocked_writer();
    interrupted_reader();
    disconnect_and_limits();
    consumed_readiness();
    puts("PASS: IPC framing, fragmentation, absolute deadlines, backpressure, EINTR and disconnects");
    return 0;
}
