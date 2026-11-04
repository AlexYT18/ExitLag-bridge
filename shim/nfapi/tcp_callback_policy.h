// Pure ownership selection and passthrough replies; no client callbacks are fabricated.
#ifndef EXITLAG_SHIM_TCP_CALLBACK_POLICY_H
#define EXITLAG_SHIM_TCP_CALLBACK_POLICY_H

#include "socket_attribution.h"
#include "pid_domain.h"
#include "../../backend/protocol.h"

namespace exl_tcp_callback_policy {

struct process_selection {
    unsigned int pid;
    exl_pid_domain::pid_origin origin;
};

static inline process_selection select_process(
    exl_socket_attribution::owner_result windows, unsigned int linux_pid)
{
    using namespace exl_socket_attribution;
    process_selection selected = {0, exl_pid_domain::pid_unknown};
    if (windows.status == owner_found && windows.pid) {
        selected.pid = windows.pid;
        selected.origin = exl_pid_domain::pid_windows;
    } else if ((windows.status == owner_none || windows.status == owner_unavailable) &&
               !windows.pid && linux_pid) {
        selected.pid = linux_pid;
        selected.origin = exl_pid_domain::pid_linux;
    }
    // Contradictory/malformed Windows tables and PID zero never select a
    // callback identity, even when the helper supplied a fallback PID.
    return selected;
}

static inline void passthrough_reply(const exl_tcp_connect_req &request,
                                     exl_tcp_connect_reply &reply)
{
    reply.tag = request.tag;
    reply.verdict = EXL_VERDICT_NO_HANDLER;
    reply.filtering_flag = request.filtering_flag;
    for (unsigned int i = 0; i < sizeof(reply.remote_address); ++i)
        reply.remote_address[i] = request.remote_address[i];
    reply.mutated_flag = reply.mutated_remote = 0;
    reply.reserved[0] = reply.reserved[1] = 0;
}

} // namespace exl_tcp_callback_policy
#endif
