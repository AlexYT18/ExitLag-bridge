# Shim IPC validation implementation

This iteration addresses baseline findings SHIM-02, SHIM-03 and SHIM-04, and
the reserved-header-flags portion of SHIM-06 from [SHIM.md](SHIM.md). No worker
lifecycle, ExitLag callback decision or active traffic scope is changed.

## Changes

- `shim/nfapi/ipc_validation.h` is a freestanding helper used by the production
  PE source and native C++ tests. Numeric IPC endpoints must be within `127/8`,
  with four nonempty decimal octets in `0..255` and optional port `1..65535`.
  Default port remains `51900`. Overflow, nonlocal destinations, extra separators,
  whitespace and trailing port text are rejected before a socket or token is used.
  Leading zeros are interpreted as decimal by this parser, not passed to an OS
  text-address parser.
- `nfapi_stub.cpp` uses `backend/protocol.h` through the validation header instead
  of duplicating the protocol. Fifteen compile-time record-size assertions catch
  packing/layout drift in both native and PE compilers. No `NF_*` exported
  function signature or callback layout is changed.
- Both shim receive buffers and frame validators now use `EXL_MAX_PAYLOAD`
  (`131072`). Valid protocol-sized UDP frames above 64 KiB no longer fail solely
  because of the shim's old receive-buffer cap. This establishes frame handling,
  not IPv6 UDP routing or broad game support.
- Both receive paths reject nonzero reserved header flags. Matching PID replies
  must contain exactly the declared path bytes, with a zero reserved field, before
  any path is copied. This prevents reading stale/out-of-frame data. Existing
  byte-to-`wchar_t` conversion and output truncation behavior are preserved;
  correct UTF-8 decoding remains a separately documented compatibility gap.

## Cloud-safe regression tests

```sh
tests/test-shim-validation.sh
ASAN_OPTIONS=detect_leaks=0 tests/test-shim-validation.sh --sanitize
```

Dependencies: Bash and a native C++11 compiler (`CXX`, default `c++`). No account,
Wine, root, network or commercial binary is required. Missing compiler returns
`77` and an explicit SKIP. Compilation/test failure returns nonzero.

Both commands executed successfully in the managed Debian 13 x86_64 environment:
**5505 assertions** per execution. This is an assertion count, not a count of
independent test scenarios. Coverage includes valid/default/boundary endpoints,
1024 generated valid endpoints, malformed and nonlocal endpoint inputs, output
canaries, every reserved header-flag bit, corrupt magic, oversized frames,
protocol-sized large UDP frames, truncated/oversized/inconsistent PID replies,
reserved fields, null/zero-capacity arguments, bounded copies and a maximum-sized
PID frame. The actual production validation helpers are executed.

AddressSanitizer and UndefinedBehaviorSanitizer were enabled in the second run.
LeakSanitizer is **SKIPPED**: the sandbox's ptrace restriction makes the default
leak check abort. Setting `detect_leaks=0` does not disable ASan bounds checking or
UBSan; it does not establish leak freedom. Suitable local/CI hosts should also
run `tests/test-shim-validation.sh --sanitize` with leak checking enabled.

## Remaining validation

Native tests do not execute Winsock, Wine callback delivery, the commercial client
or Linux packet redirection. PE build/export consistency evidence is recorded in
the aggregate test report. Runtime Wine transport tests and Levels 2/3 remain
distinct from these pure validation tests.

Outstanding issues include worker join/cleanup, session-scoped process origins,
full-tuple Windows attribution, complete handshake sequencing/record validation,
UTF-8 conversion and unsupported SDK semantics. See the baseline audit and roadmap.
