#ifndef EXITLAG_IPC_TRANSPORT_H
#define EXITLAG_IPC_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include "protocol.h"

/* Absolute CLOCK_MONOTONIC deadline, shared by all parts of one operation. */
typedef int64_t exl_ipc_deadline;

exl_ipc_deadline exl_ipc_deadline_after(int timeout_ms);
/* Recheck after nested RPCs may have consumed an earlier poll notification.
 * 1 means readable/closed/error, 0 means no event, -1 means invalid fd/syscall.
 * This is a nonblocking hint; complete frame reads still need a deadline. */
int exl_ipc_ready(int fd);
int exl_ipc_read_exact(int fd, void *buffer, size_t length, exl_ipc_deadline deadline);
int exl_ipc_write_exact(int fd, const void *buffer, size_t length, exl_ipc_deadline deadline);
int exl_ipc_send_frame(int fd, unsigned short type, const void *payload,
                       unsigned int length, exl_ipc_deadline deadline);
int exl_ipc_recv_frame(int fd, struct exl_header *header, void *payload,
                       size_t capacity, exl_ipc_deadline deadline);

#endif
