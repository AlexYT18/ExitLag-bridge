#ifndef EXL_PROCESS_IDENTITY_H
#define EXL_PROCESS_IDENTITY_H

#include <stddef.h>
#include <sys/types.h>

struct process_identity {
    pid_t pid;
    uid_t uid;
    unsigned long long start_time; /* /proc/PID/stat field 22, kernel clock ticks */
};

/* Return 1 only for a stable kernel identity. All four status UIDs must equal
 * the proc directory owner; setuid/fsuid/non-dumpable mismatches fail closed.
 * On failure the output snapshot is zeroed. No argv/comm text is trusted. */
int process_identity_read(pid_t pid, struct process_identity *identity);

/* Reopen /proc/PID, compare birth time and UID before/after an exact socket fd
 * scan. Return 0 on errors, exit, changed generation/credentials or no owner.
 * This bounded recheck cannot lock against a later close or same-UID exec. */
int process_identity_holds_socket(const struct process_identity *identity,
                                  unsigned long inode);

/* Pure parsers used by the proc reader and fixture tests. Inputs include the
 * final newline and may contain newlines/parentheses inside stat's comm. */
int process_identity_parse_stat(const char *text, size_t length, pid_t expected_pid,
                                unsigned long long *start_time);
int process_identity_parse_status(const char *text, size_t length, pid_t expected_pid,
                                  uid_t proc_owner, uid_t *uid);

#endif
