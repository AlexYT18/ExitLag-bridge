# Shim worker lifecycle

`nf_init` owns a single session and its callback handler. Repeated or concurrent
initialization returns `NF_STATUS_FAIL` without replacing the active handler.
An absent helper or unset `EXITLAG_NETD` still permits initialization; a worker
creation failure revokes and reaps the partially created session.

An external `nf_free` revokes synchronous UDP authority, requests both workers to
stop, shuts down the currently owned IPC socket and joins retained worker handles
before clearing the handler or allowing a new session. Only the worker closes its
socket; shutdown and close use a separate short gate to prevent numeric handle
reuse races. Concurrent external frees wait for that generation's completion.
The lifecycle gate is never held during join, so callback reentry cannot deadlock
on that gate. Winsock startup/cleanup and worker HANDLE close are paired.

When a callback itself calls `nf_free`, it revokes the session and returns without
joining itself. This is **deferred teardown**: retain the handler and DLL until an
external `nf_free` completes. A new `nf_init` fails while those workers remain
active; if they have already exited, it reaps their signaled handles before
starting a new session. This does not promise synchronous destruction from inside
a callback or forcibly terminate foreign callback code.

The slot used for Windows TLS remains allocated for the DLL lifetime. Each worker
clears its context before releasing its private buffers. The PID domain registry
remains conservative across sessions because numeric PID-domain collisions can
still be referenced by SDK calls.

An external free deliberately waits for callbacks to return. A hung proprietary
callback or a long research-only injection command can delay teardown; thread
termination would leave callback object ownership unsafe. Loopback connect uses nonblocking 100 ms select slices with a five-second
deadline, so a dropped SYN cannot indefinitely pin that connect loop. Wine's socket
behavior still requires runtime validation. Unloading the DLL
from an active callback is unsupported.

## Validation

```sh
bash tests/test-shim-lifecycle.sh
bash tests/test-shim-lifecycle.sh --sanitize
bash shim/nfapi/build.sh
```

The portable tests execute the production coordinator with actual native worker
threads: concurrent init/free, partial startup failure, duplicate init, callback
self-free, callback reentry while another caller joins, deferred reaping, and 100
restart cycles. ASan/UBSan exercise the same cases. The PE build checks imported
API linkage. These are cloud-safe tests, not evidence of runtime Wine/ExitLag or
game compatibility. Live Wine stress testing remains outstanding.
