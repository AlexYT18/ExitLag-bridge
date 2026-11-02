# Validation matrix

This matrix describes test scope and acceptance evidence. It does not claim
that every row has passed in this checkout. See [testing](testing.md) for the
runner, the [initial audit](audit/INITIAL_AUDIT.md) for the baseline and the
[roadmap](audit/ROADMAP.md) for planned follow-up work.

## Automated checks

| Group | Examples | Requirements | Evidence boundary |
|---|---|---|---|
| Linux unit | builds, mapping, discovery, assistant, setup simulation, selected RPC cases | compiler/LLVM tools, libmnl, Python and Wine as required by the script | local logic and fixtures; no real game |
| Installed-client unit | nfapi imports/exports, doctor self-check | user-supplied official client files | static compatibility/diagnostics; no login or relay proof |
| Privileged IPC | authentication, malformed framing, token rotation, reconnect | root and relevant tools; several cases use `--no-queue` | observed corpus only; a no-queue run does not exercise nftables |
| Lifecycle | ownership refusal, TERM/INT cleanup, next-start SIGKILL recovery, probe fail-open | root plus usable NFQUEUE/nftables and Wine for shim scenarios | recovery scenarios differ; no guarantee of established relay-session survival |
| IPv6 rewrite | target validation, real connection, reverse translation, table cleanup | root, netfilter and IPv6; synthetic peer | Linux TCP mechanism, not vendor IPv6 title support |
| External Wine prefix | mapped probe redirect and unmapped control | root, running official ExitLag, Wine prefixes | probe traffic with a live callback, not full gameplay |
| Installer/Mac targeted suites | setup, ownership, lease, package and native routing fixtures | platform-specific tools/capabilities | see each suite and package record; not all run through `tests/run-all.sh` |

The runner prints actual totals. A missing official client produces a declared
skip for installed-client checks; missing privileges or a running client can
skip their tiers. Other dependencies can fail a test. Record internal skips
and environment limitations too. Neither a successful wrapper exit nor the
existence of a test file is sufficient to label every underlying case passed.

## Manual acceptance scenarios

These are instructions for evidence to collect, not a statement that each check
was completed during development. Private earlier reports are summarized in
[compatibility](compatibility.md) and [routing stages](pipeline-stages.md).

| Scenario | Evidence to record | Requires |
|---|---|---|
| Fresh GUI setup/login | platform, vendor/Wine build, wizard result, user ownership and login outcome | clean supported OS, official installer/account |
| Supported TCP title | new game flow, callback decision, actual bidirectional relay traffic and gameplay duration | account + game |
| UDP title | callback shape, payload/destination checks, both traffic directions, session outcome | account + UDP game; distinguish login probes from gameplay |
| Proton launch | exact prefix mapping, launch method, real socket owner and routed/unmapped outcomes | account + Steam/Proton title |
| ExitLag restart | existing-session outcome separately from new callback/connection recovery | account + game |
| Game restart | new connection attribution and redirect, stale state and cleanup | account + game |
| Helper/proxy failure | behavior of existing translated flows and new direct flows recorded separately | isolated controlled environment; account/game for live claims |
| Network reconnect | interface down/up or actual connectivity change, flow expiry, new connection and gameplay outcome | controlled network + account/game |
| Sleep/reboot | helper/lease/firewall state and subsequent launch/connect result | supported physical OS |
| Cleanup | owned helper, table, token, pidfile and stale state after each termination mode | matching privileges |

SIGKILL recovery is checked on the next authorized start; it cannot be described
as cleanup performed by a signal trap. A physical reconnect is different from
contacting an unreachable endpoint. Longer soak, second-machine testing and a
minimum-OS run require their own dated records.

## Result format

For each run, record source commit, package/runtime hashes, OS/kernel and CPU,
client/Wine/game versions, commands, date, exit codes, pass/fail/skip counts and
redacted observations. Identify synthetic peers, unavailable capabilities,
absent account access and incomplete steps explicitly.

There is no timeless "current pass count" in this document. Historical release
validation remains scoped to its recorded artifacts and environment; new work
must produce a new record. A skip is never a pass, and a dashboard entry alone
never upgrades a game to working relay gameplay.
