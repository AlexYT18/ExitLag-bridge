# Surviving ExitLag updates

ExitLag auto-updates, and this project is not told when it does. The shim
reproduces a private ABI (`nfapi`) against a specific build, so an update can
change what the client expects without any visible symptom until it crashes or
silently stops being steered.

## Client 5.24.0 review — 2026-11-02

The [official download page](https://www.exitlag.com/download) now links to
`SetupExitLag-5.24.0-x64.exe`. Its AMD64 application payload was checked against
the released Mac shim and Wine 11.17 Staging in a separate, account-free prefix.

| Check | Result |
|---|---|
| Main application's `nfapi` imports | The same 18 symbols as client 5.23.3; none added or removed. |
| Driver-registration helper's `nfapi` imports | Two symbols; all 20 symbols required across both modules are provided by the shim. |
| Main application's Wine imports | 18 system DLLs checked; all 11 absent named exports have existing crash guards, and 31 ordinal imports resolve. |
| Fresh-prefix WMI and shim configuration | Passed using the existing compatibility components. |
| Account-free process startup | Stayed running for 45 seconds with Vulkan/basic Qt rendering; no sign-in or game traffic. This was a process-liveness check, not visual dashboard verification. |
| Login and live game routing | Not tested with 5.24.0; earlier gameplay results do not establish this version's behavior. |

No shim change was required by these import checks. They do not verify callback
behavior, authentication, route analysis, or a complete game session. Linux
runtime testing with 5.24.0 remains outstanding. Keep the client version in new
compatibility reports.

The review used extracted AMD64 files rather than completing the graphical
vendor installer. The installer contains both AMD64 and ARM64 runtime variants;
an extraction must preserve collisions and select the AMD64 files. Normal users
should continue through the official wizard described in the setup guide.

Public download identities, for reproducing this review:

```text
SetupExitLag-5.24.0-x64.exe SHA-256:
8e1482aa23169ee442e368fad1ad0c5767d20ce596ab8129b7e4cce24d18dc86
ExitLag.exe SHA-256:
9baa794c84c5a90f1b2c84130877ba8ae5a8b1867ece00866dd3b03d0eccc106
```

These hashes identify the downloaded files; they are not a replacement for
publisher-signature verification. No vendor binaries, account state, or raw
runtime logs are included in this repository.

**The updater is not disabled.** Blocking it would leave users on an old client
against a live service, and ExitLag's own auth and relay code is the part we
deliberately do not touch. Instead, updates are detected and verified.

## The flow

```text
launch
  |
  +-- build matches the recorded known-good?  -- yes --> run
  |
  no
  |
  +-- re-derive the ABI this build actually needs
        |
        +-- still compatible? -- yes --> WARN loudly, run,
        |                                invite the user to record it
        |
        no --> REFUSE to start, explain exactly what changed
```

Implemented in `tools/run-exitlag-production.sh`. The research launchers do not
gate, so deliberate work on a new build is still possible.

## What is tracked

**`tools/check-exitlag-version.sh`** records the identity of the build the
runtime was verified against: product version, SHA-256, size, and how many of
the guarded imports are present. Exit 0 unchanged, 1 drift, 2 no baseline.
Record a build as known-good with `--record`.

This is identity, not compatibility. A hash tells you *something* changed, not
whether it matters.

**`tools/check-exitlag-abi.sh`** answers whether it matters, by re-deriving the
two things the shim actually depends on from the binaries present right now:

1. **Every `nfapi` symbol ExitLag imports is exported by the shim.** The
   decorated import list is read from ExitLag's import table and compared with
   the shim's export table. A symbol ExitLag imports that the shim lacks is
   fatal: Wine resolves it to a stub that raises a non-continuable exception.

2. **Every import Wine does not provide is covered by a crash guard.** For each
   DLL ExitLag imports from that Wine also ships, the imports are diffed against
   Wine's own exports; anything missing must appear in the shim's guard table.
   A new uncovered one is a crash waiting for the user to open the wrong page.

This is why a bare hash pin would be wrong: the hash changes on every update,
while the ABI usually does not. Checking the ABI lets a routine update through
and stops a breaking one.

Example report for the main executable (the setup check also examines the
registration helper):

```text
== nfapi ABI ==
  ExitLag imports : 18 symbols
  shim exports    : 20 symbols
  OK: the shim provides every nfapi symbol this build imports

== Wine missing-import crash guards ==
  OK: every import Wine does not provide is covered by a crash guard
      (18 DLLs checked, 11 guards installed)
```

## What is not checked automatically

- **Behaviour changes behind an unchanged ABI.** If ExitLag keeps the same
  exports but changes what it does with them — a different callback contract, a
  new filtering-rule shape — no static check will see it. The regression tests
  are what catch that, and they need a real client.
- **WMI and GUI assumptions.** The client needs
  `Win32_LogicalDiskRootDirectory`, which Wine does not implement, and renders
  with `QSG_RHI_BACKEND=opengl`. A UI rewrite could change either. These are
  covered by `tools/exitlag-doctor.sh` reporting the environment, not by a
  version check.
- **`libexitlag.dll`.** Its version is recorded as part of the build identity
  but the shim does not link against it, so there is nothing to verify.
- **The legacy NDIS path.** `ndisapi.dll` / `ndextlag.sys` are not used; the
  redirection method must stay Automatic/WFP.

## When a check fails

Drift reported, ABI still fine — nothing is wrong. Run it, and once it behaves,
`tools/check-exitlag-version.sh --record`.

ABI incompatible — the report names the exact symbols. For a missing `nfapi`
export, add it to `shim/nfapi/nfapi_stub.cpp` and rebuild; the export must match
the decorated name exactly. For an unguarded import, add it to the guard table
(`docs/wine-stub-crash-guards.md` describes the mechanism). Then re-run the
regression suite before recording the new build.
