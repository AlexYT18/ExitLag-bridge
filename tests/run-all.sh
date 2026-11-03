#!/usr/bin/env bash
# Regression suite entry point.
#
#   tests/run-all.sh unit          no privileges, no ExitLag  (any contributor)
#   tests/run-isolated.sh         adds netfilter tests in disposable namespaces
#   sudo tests/run-all.sh live     adds tests needing a running ExitLag
#   sudo tests/run-all.sh all      everything available in this environment
#
# Default is `unit`. Public tiers are cumulative; system-only is used by the
# isolated wrapper to avoid running unprivileged permission tests as root.
# A tier whose requirements are not met
# is reported as SKIP with the reason, never as a pass.
set -uo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

have_root()    { [[ $EUID -eq 0 ]]; }
have_exitlag() { pgrep -f '^\./ExitLag\.exe' >/dev/null 2>&1; }
have_isolation() {
    [[ ${EXITLAG_TEST_ISOLATED:-} == 1 && -n ${EXITLAG_TEST_HOST_NETNS:-} && \
       -n ${EXITLAG_TEST_HOST_PIDNS:-} ]] || return 1
    [[ "$(readlink /proc/self/ns/net)" != "$EXITLAG_TEST_HOST_NETNS" && \
       "$(readlink /proc/self/ns/pid)" != "$EXITLAG_TEST_HOST_PIDNS" ]]
}
# The official client is not redistributable, so a fresh checkout will not have
# it. Tests that inspect it must skip with a reason, not look like breakage.
have_exitlag_files() { [[ -f "${EXITLAG_APP_DIR:-$repo_root/runtime/app-shim}/ExitLag.exe" ]]; }

run_test() {   # run_test <name> <requirement: none|root|exitlag> <command...>
    local name="$1" req="$2"; shift 2
    case "$req" in
        root)    have_root    || { results+=("SKIP  $name (needs sudo)"); skip=$((skip+1)); return; } ;;
        isolated) if ! have_root || ! have_isolation; then
                     results+=("SKIP  $name (requires tests/run-isolated.sh disposable network/PID namespaces)")
                     skip=$((skip+1)); return; fi ;;
        multiuid) if ! have_root || ! command -v sudo >/dev/null ||
                  [[ $(awk '$1 == 0 {print $3}' /proc/self/uid_map) == 1 ]]; then
                     results+=("SKIP  $name (requires root, sudo and multiple mapped UIDs)")
                     skip=$((skip+1)); return; fi ;;
        exitlag) have_root    || { results+=("SKIP  $name (needs sudo)"); skip=$((skip+1)); return; }
                 have_exitlag || { results+=("SKIP  $name (ExitLag is not running)"); skip=$((skip+1)); return; } ;;
        installed) have_exitlag_files || {
                     results+=("SKIP  $name (the official ExitLag client is not installed)")
                     skip=$((skip+1)); return; } ;;
    esac
    printf '\n--- %s\n' "$name"
    # Unprivileged tests run as the invoking user even under sudo: building as
    # root would leave root-owned objects in a user-owned tree and break the
    # next plain build.
    local -a cmd=("$@")
    if [[ "$req" == none && -n "${SUDO_USER:-}" ]]; then
        cmd=(sudo -u "$SUDO_USER" "--preserve-env=PATH,HOME" env "$@")
    fi
    local log="$outdir/${name//[^a-zA-Z0-9]/_}.log" status=0
    "${cmd[@]}" >"$log" 2>&1 || status=$?
    if (( status == 0 )); then
        results+=("PASS  $name"); pass=$((pass+1)); printf '    PASS\n'
    elif (( status == 77 )); then
        local reason
        reason="$(tail -1 "$log")"
        results+=("SKIP  $name (${reason:-test returned skip code 77})")
        skip=$((skip+1)); printf '    SKIP: %s\n' "${reason:-test returned skip code 77}"
    else
        results+=("FAIL  $name  (exit $status; see $log)"); fail=$((fail+1))
        printf '    FAIL -- last lines:\n'; tail -5 "$outdir/${name//[^a-zA-Z0-9]/_}.log" | sed 's/^/      /'
    fi
}

main() {
local tier="${1:-unit}"
case "$tier" in
    unit|system|system-only|live|all) ;;
    *) printf 'Unknown test tier: %s. Expected unit, system, system-only, live or all.\n' "$tier" >&2; return 2 ;;
esac
local stamp
stamp="$(date +%Y%m%dT%H%M%S)-$$"
outdir="$repo_root/runtime/logs/suite-$stamp"
mkdir -p "$outdir"
pass=0; fail=0; skip=0; results=()
echo "regression suite: tier=$tier"
echo "logs: $outdir"
have_root    && echo "  root: yes"    || echo "  root: no (system/live tiers will skip)"
have_exitlag && echo "  ExitLag: running" || echo "  ExitLag: not running (live tier will skip)"

# ---------------------------------------------------------------- unit
if [[ "$tier" == unit || "$tier" == system || "$tier" == live || "$tier" == all ]]; then
    echo; echo "===== unit ====="
    run_test "shim builds"            none "$repo_root/shim/nfapi/build.sh"
    run_test "helper builds"          none make -B -C "$repo_root/backend"
    run_test "TCP socket attribution" none make -B -C "$repo_root/backend" check-tcp-attribution
    run_test "process birth identity" none make -B -C "$repo_root/backend" check-process-identity
    run_test "NFQUEUE verdict encoding" none make -B -C "$repo_root/backend" check-nfq-verdict
    run_test "shim socket attribution" none bash "$repo_root/tests/test-shim-attribution.sh"
    run_test "shim PID domains"       none bash "$repo_root/tests/test-shim-pid-domain.sh"
    run_test "nfapi ABI matches ExitLag" installed "$repo_root/tools/check-exitlag-abi.sh"
    run_test "identity map pos/neg"   none "$repo_root/tests/test-identity-map.sh"
    run_test "crash-guard build only"  none "$repo_root/tests/build-nfapi-compat-smoketest.sh"
    run_test "doctor self-check"      installed "$repo_root/tools/exitlag-doctor.sh"
    run_test "doctor diagnoses"       none "$repo_root/tests/doctor-test.sh"
    run_test "RPC surface scope"      none "$repo_root/tests/rpc-surface-test.sh"
    run_test "process discovery"      none "$repo_root/tests/discovery-test.sh"
    run_test "identity-map assistant" none "$repo_root/tests/identity-assistant-test.sh"
    run_test "setup simulation"       none "$repo_root/tests/setup-simulation-test.sh"
    run_test "integration peer units" none python3 "$repo_root/tests/test-integration-support.py"
    run_test "process picker model" none python3 "$repo_root/tests/test_process_picker.py"
    run_test "game mapping editor" none python3 "$repo_root/tests/test_game_picker.py"
    run_test "Linux source packaging" none python3 "$repo_root/tests/test_linux_packaging.py"
    run_test "Tk process picker integration" none python3 "$repo_root/tests/gui-picker-smoke.py"
fi

# ---------------------------------------------------------------- system
if [[ "$tier" == system || "$tier" == system-only || "$tier" == live || "$tier" == all ]]; then
    echo; echo "===== system (needs root) ====="
    run_test "IPC security negatives" multiuid "$repo_root/tests/ipc-security-test.sh"
    run_test "IPC hostile input"      root "$repo_root/tests/ipc-fuzz-test.sh"
    run_test "lifecycle hardening"    isolated "$repo_root/tests/harden-runtime-test.sh"
    run_test "IPv6 active rewrite"    isolated "$repo_root/tests/ipv6-redirect-test.sh"
    run_test "TCP synthetic redirect" isolated python3 "$repo_root/tests/test-tcp-redirect.py"
    run_test "TCP stale-map authorization" isolated python3 "$repo_root/tests/test-tcp-authorization.py"
    run_test "UDP synthetic observe"  isolated python3 "$repo_root/tests/test-udp-observe.py"
    run_test "UDP synthetic steer"    isolated python3 "$repo_root/tests/test-udp-observe.py" --steer
fi

# ---------------------------------------------------------------- live
if [[ "$tier" == live || "$tier" == all ]]; then
    echo; echo "===== live (needs root + running ExitLag) ====="
    run_test "external Wine prefix routing" exitlag "$repo_root/tests/validate-external-prefix.sh"
fi

# ---------------------------------------------------------------- summary
echo; echo "===== summary ====="
printf '%s\n' "${results[@]}"
printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"

if (( skip )); then
    echo
    echo "Skipped tests are not passes. To run them:"
    have_root          || echo "  - re-run with sudo for the system tier"
    have_exitlag_files || echo "  - install the official ExitLag client (see README.md); it is not redistributable, so a fresh checkout will not have it"
    have_exitlag       || echo "  - start ExitLag (tools/run-exitlag-production.sh) for the live tier"
fi

cat <<'NOTE'

Not automated (need a real game and a human):
  - TCP steering with live WoW world traffic
  - UDP take-and-reinject against a real game's datagrams
  - Proton routing with a real title
  See docs/architecture.md for what each of those proved.
NOTE
return $(( fail > 0 ))
}

# Sourcing only exposes the runner functions to account-free regression tests.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
