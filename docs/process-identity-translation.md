# Process identity translation

The native backend attributes sockets to real processes and translates only
explicit mappings to a Windows identity understood by ExitLag. Native source
matching uses `/proc/<pid>/exe`. Neither argv tokens
nor argv[0] prove executable identity, even if they exactly match a configured
source. Legacy argv-only map entries are rejected with a migration diagnostic;
replace them with the canonical executable that actually owns the socket.
Without a map, the backend reports only the kernel-reported executable. It no
longer derives a Windows image from command-line strings. Wine/Proton identity
translation therefore requires a reviewed explicit mapping.

## Mapping format

Native rows contain `SOURCE<TAB>WINDOWS_PATH`. Prefix rows require
`wineprefix:DIR<TAB>WINDOWS_PATH<TAB>OWNER_EXE`, with literal Tabs.

```text
/opt/games/example/game\tC:\Games\Example\game.exe
wineprefix:/home/USER/Games/example-prefix\tC:\Games\Example\game.exe\t/absolute/verified/runtime
```

In the example above replace `\t` with an actual Tab. The source is the real
network-owning native executable, or `wineprefix:` followed by the canonical
Wine/Proton prefix. `OWNER_EXE` must be the actual socket owner's executable
observed through `/proc/PID/exe`, such as the exact approved runtime used on
that host. No runtime name is inferred. Both executable and prefix paths are
canonicalized; spaces and symlinks are accepted. Executable paths must resolve
to existing regular files with execute permission bits. Windows paths must
identify the game selected in ExitLag; the project does not know the service's
authoritative catalogue.

Prefix mapping requires both the exact executable and matching canonical
`WINEPREFIX`. A native process setting that environment variable alone is not
authorized. Separate rows may approve distinct executables for the same prefix;
duplicate canonical executable/prefix keys are refused.

This is a same-user, prefix-wide allowlist. A user who can run an approved
runtime with that prefix can launch another application under it. It does not
attest which Windows image is running. Use dedicated game prefixes and protect
approved executable files against replacement. PID reuse, process-exit races,
shared socket ownership and runtime-specific attribution still need further
hardening and live validation. `STEAM_COMPAT_DATA_PATH` is an advisory discovery
hint; runtime authorization requires the observed owner's `WINEPREFIX`.

## Migration and assisted configuration

The desktop [running-game picker](game-selection.md) captures the observed
executable/prefix and offers real mapped PE images or an actual file picker.
It rechecks process generation, credentials, executable, held sockets and image
metadata before producing a row. It derives Windows paths from verified Wine
drives, without treating them as an authoritative ExitLag catalogue match.
Native games with no established Windows identity still require explicit input.

Old two-column prefix-only rows fail startup with `requires OWNER_EXE third
column`. Select the real game socket owner, review its exact executable and
prefix, and add the third column. Do not copy a generic `wine` path from an
example or accept a process name as proof. Native two-column rows are preserved.

The assistant requires explicit owner approval for prefix entries:

```sh
tools/identity-map-assistant.py --pid PID \
    --windows-identity 'C:\Games\Example\game.exe' \
    --owner-exe /absolute/verified/runtime --append runtime/games.map
```

It checks that the approved path matches the discovered executable; a discovery
snapshot is advisory and not a race-free process attestation. The Steam scanner
keeps candidate rows commented out and emits a runtime confirmation placeholder.
No generated candidate is a verified ExitLag identity or compatibility result.

The Linux desktop editor writes a private mapping file. The installed supervisor
checks ownership, permissions and syntax, then copies data into its protected
runtime directory. User-selected paths are data; they are not executed as root.
The firewall queue is scoped to the authorized user.

Cloud-safe regression coverage: `tests/test-identity-map.sh` exercises synthetic
IPC identity resolution, native/symlink positives, argv and argv[0] negatives,
exited processes, exact owner/prefix positives and negatives, malformed map
rejection and no-map spoofing. `python3 tests/test_identity_tools.py` tests the
assistant and disabled scanner candidates with mocks and no network privileges.
These tests do not establish real Wine callbacks or live relayed gameplay.

The macOS adapter instead uses exact allowlisted native executable paths and a
separate user-mode Wine socket companion for each supported WoW client. Its
root helper receives a bounded enable/disable lease, not arbitrary commands.

Historical local network traces are omitted. See
[compatibility](compatibility.md) for tested scope and [architecture](architecture.md)
for details. A mapping's presence alone does not prove real relayed gameplay.
