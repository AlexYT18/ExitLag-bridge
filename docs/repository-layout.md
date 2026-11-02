# Repository layout

This is a public source snapshot. Earlier research trees, private captures and
configured Wine prefixes are not tracked here. Historical references to them
in development notes describe material unavailable in this checkout; they are
not installation prerequisites. See the [initial audit](audit/INITIAL_AUDIT.md)
and [roadmap](audit/ROADMAP.md).

## Source and installation

```text
backend/          Linux NFQUEUE helper, wire protocol, nftables and runner lifecycle
shim/nfapi/       Windows-side nfapi compatibility DLL
shim/nfextlag/    presence-only driver compatibility stub
wine-wbemprox/   Wine WMI patch and developer build scripts
macos/           native Mac routing backend and app/privileged-helper sources
installers/      shared setup, pinned runtime catalog and Linux packaging
```

`backend/exitlag-netd.c` coordinates attribution, callbacks and packet decisions.
`tcp_attribution.{c,h}` matches complete TCP tuples; `process_identity.{c,h}`
checks process birth, UID and held sockets. `ipc_transport.{c,h}` bounds IPC
transactions. `nfq_verdict.{c,h}` encodes bounded NFQUEUE verdicts and the
transient priority authorization consumed by nft rules.
`backend/protocol.h` defines the EXL1 wire layout. The active developer runners
use `backend/runtime-guard.sh` for lock/pidfile ownership and recovery, and
`nft-setup.sh` / `nft-teardown.sh` for the dedicated firewall table. Packaged
routing uses installed supervisors; developer runners are not the ordinary
user launch path.

The WMI patch can be built with a project-local Wine for developer use.
Packaged setup instead prepares the pinned runtime and replacement payload
through `installers/`. See [Wine setup](wine-setup.md) and the
[installer guide](../installers/README.md).

## Developer tools

```text
tools/exitlag-setup.sh             install / status / uninstall developer setup
tools/exitlag-doctor.sh            pre-flight environment diagnostics
tools/discover-game-processes.py   network-owning process discovery
tools/identity-map-assistant.py    mapping with a confirmed Windows identity
tools/run-exitlag-production.sh    launcher without research behavior overrides
tools/run-exitlag-gameprefix.sh    diagnostic launcher
tools/check-exitlag-version.sh     comparison with a local build baseline
tools/check-exitlag-abi.sh         imported symbols and Wine guard compatibility
tools/audit-source.py             source privacy checks
```

The `install-wbemprox-prefix-override.sh` / restore scripts retain an earlier
experiment's diagnostic/reversal path. The install script refuses that obsolete
deployment method; it is not a working alternative WMI installer.

## Tests, documentation and licenses

`tests/run-all.sh` selects the Linux unit/system/live tiers. Other targeted
suites live beside the Linux installer, Mac backend and app. The presence of a
test file does not mean it is registered in that runner or has passed in the
current environment. See [testing](testing.md) and the [test matrix](test-matrix.md).

`docs/` contains user/technical documentation and the static project website.
`docs/releases/` contains historical release validation records, not current
runtime state. `docs/audit/` contains the source audit, inventory, evidence and
planned follow-up work. `LICENSE`, `LICENSES/` and `THIRD_PARTY.md` describe the
first-party license and retained upstream notices; original notices retain
their own terms.

## Generated and private state

Developer scripts may create `runtime/` for Wine prefixes, baselines, logs and
session metadata, and `vendor/` for build inputs. Generated build/output trees
are ignored as listed in `.gitignore`. These directories are not tracked
research archives and must not be published wholesale. Installed applications
also keep user/account state outside the source tree.

The production launcher clears synthetic-injection and export-policy research
overrides. Source build, packaging and tests should not require an omitted
private trace or research tree. If a diagnostic message points to an absent
historical file, report that reference rather than treating it as bundled
runtime evidence.
