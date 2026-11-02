#define _POSIX_C_SOURCE 200809L
#include "ipc_transport.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

exl_ipc_deadline exl_ipc_deadline_after(int timeout_ms)
{
    if (timeout_ms <= 0) { errno = EINVAL; return -1; }
    int64_t now = monotonic_ms();
    return now < 0 ? -1 : now + timeout_ms;
}

static int wait_ready(int fd, short events, exl_ipc_deadline deadline)
{
    for (;;) {
        int64_t now = monotonic_ms();
        if (now < 0) return -1;
        int64_t remaining = deadline - now;
        if (remaining <= 0) { errno = ETIMEDOUT; return -1; }
        struct pollfd pfd = { fd, events, 0 };
        int result = poll(&pfd, 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return -1;
        if (!result) { errno = ETIMEDOUT; return -1; }
        if (pfd.revents & POLLNVAL) { errno = EBADF; return -1; }
        /* Read/write reports the actual EOF or socket error after HUP/ERR. */
        if (pfd.revents & (events | POLLHUP | POLLERR)) return 0;
    }
}

int exl_ipc_read_exact(int fd, void *buffer, size_t length, exl_ipc_deadline deadline)
{
    unsigned char *bytes = buffer;
    while (length) {
        if (wait_ready(fd, POLLIN, deadline) != 0) return -1;
        ssize_t count = recv(fd, bytes, length, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count < 0) return -1;
        if (!count) { errno = ECONNRESET; return -1; }
        bytes += count;
        length -= (size_t)count;
    }
    return 0;
}

int exl_ipc_write_exact(int fd, const void *buffer, size_t length, exl_ipc_deadline deadline)
{
    const unsigned char *bytes = buffer;
    while (length) {
        if (wait_ready(fd, POLLOUT, deadline) != 0) return -1;
        ssize_t count = send(fd, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count < 0) return -1;
        if (!count) { errno = EPIPE; return -1; }
        bytes += count;
        length -= (size_t)count;
    }
    return 0;
}

int exl_ipc_send_frame(int fd, unsigned short type, const void *payload,
                       unsigned int length, exl_ipc_deadline deadline)
{
    if (length > EXL_MAX_PAYLOAD || (length && !payload)) { errno = EMSGSIZE; return -1; }
    struct exl_header header = { EXL_MAGIC, type, 0, length };
    if (exl_ipc_write_exact(fd, &header, sizeof(header), deadline) != 0) return -1;
    return exl_ipc_write_exact(fd, payload, length, deadline);
}

int exl_ipc_recv_frame(int fd, struct exl_header *header, void *payload,
                       size_t capacity, exl_ipc_deadline deadline)
{
    if (exl_ipc_read_exact(fd, header, sizeof(*header), deadline) != 0) return -1;
    if (header->magic != EXL_MAGIC || header->flags || header->length > EXL_MAX_PAYLOAD) {
        errno = EPROTO;
        return -1;
    }
    if (header->length > capacity || (header->length && !payload)) { errno = EMSGSIZE; return -1; }
    return exl_ipc_read_exact(fd, payload, header->length, deadline);
}
