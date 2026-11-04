#!/usr/bin/env bash
# Experimental synchronous multi-endpoint UDP plus the existing TCP path.
# The authenticated client supplies posts; this runner does not select relays
# or imply that a game's UDP traffic has been verified through ExitLag.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
duration="${1:-}"
queue="${QUEUE_NUM:-0}"
udp_queue="${UDP_QUEUE_NUM:-1}"
port="${EXL_PORT:-51900}"
log="${NETD_LOG:-$repo_root/runtime/logs/netd-udp-multi-$(date +%Y%m%dT%H%M%S).log}"
table_installed=0
source "$repo_root/backend/runtime-guard.sh"
mapfile -t identity_args < <(runtime_identity_args)

if [[ $EUID -ne 0 ]]; then echo "run with sudo (NFQUEUE and raw UDP need root)" >&2; exit 1; fi
: "${TEST_DEST:?set TEST_DEST=<ip|any> for the TCP path}"
: "${UDP_TEST_DEST:?set UDP_TEST_DEST=<ip|any> explicitly}"
: "${EXL_USER_UID:?set EXL_USER_UID to the authorized game user}"
: "${EXITLAG_IDENTITY_MAP:?set reviewed game mappings before multi-endpoint UDP}"
if ! [[ "$EXL_USER_UID" =~ ^[0-9]+$ ]] || (( EXL_USER_UID < 1000 )); then
    echo "EXL_USER_UID must identify the authorized game user" >&2; exit 2
fi
if [[ "${ENABLE_REDIRECT:-}" != 1 || "${ENABLE_UDP_STEER:-}" != 1 || "${ENABLE_UDP_MULTI:-}" != 1 ]]; then
    echo "refusing without ENABLE_REDIRECT=1, ENABLE_UDP_STEER=1 and ENABLE_UDP_MULTI=1" >&2; exit 2
fi
if [[ "$queue" == "$udp_queue" ]]; then echo "QUEUE_NUM and UDP_QUEUE_NUM must differ" >&2; exit 2; fi

runtime_guard_acquire "$repo_root"
mkdir -p "$(dirname "$log")"
cleanup() {
    set +e
    [[ -n "${exitlag_timer_pid:-}" ]] && kill "$exitlag_timer_pid" 2>/dev/null
    [[ -n "${netd_pid:-}" ]] && kill "$netd_pid" 2>/dev/null
    [[ -n "${netd_pid:-}" ]] && wait "$netd_pid" 2>/dev/null
    if (( table_installed )); then "$repo_root/backend/nft-teardown.sh" >/dev/null 2>&1; fi
    [[ -n "${netd_pid:-}" ]] && runtime_guard_clear_helper "$netd_pid"
    if (( table_installed )); then
        echo "teardown complete: $(nft list table inet exitlag >/dev/null 2>&1 && echo 'TABLE STILL PRESENT' || echo 'no exitlag table')"
    else
        echo "teardown complete: no table was installed by this run"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

runtime_guard_spawn_helper "$repo_root/backend/exitlag-netd" --queue "$queue" --udp-queue "$udp_queue" \
    --port "$port" --apply-tcp --apply-udp --udp-multi --allow-udp-remote-redirect \
    "${identity_args[@]}" --log "$log"
netd_pid=$exitlag_spawned_pid
runtime_guard_record_helper "$netd_pid"
for _ in {1..100}; do
    if grep -q "bound NFQUEUE $queue" "$log" 2>/dev/null &&
       grep -q "bound UDP NFQUEUE $udp_queue" "$log" 2>/dev/null; then break; fi
    kill -0 "$netd_pid" 2>/dev/null || { echo "exitlag-netd exited during startup; see $log" >&2; exit 3; }
    sleep 0.02
done
if ! grep -q "bound NFQUEUE $queue" "$log" 2>/dev/null ||
   ! grep -q "bound UDP NFQUEUE $udp_queue" "$log" 2>/dev/null; then
    echo "exitlag-netd did not become ready; see $log" >&2; exit 3
fi

QUEUE_NUM="$queue" TEST_DEST="$TEST_DEST" UDP_QUEUE_NUM="$udp_queue" \
UDP_TEST_DEST="$UDP_TEST_DEST" UDP_TEST_PORT="${UDP_TEST_PORT:-}" EXL_USER_UID="$EXL_USER_UID" \
ENABLE_UDP_OBSERVE=1 ENABLE_UDP_STEER=1 ENABLE_UDP_MULTI=1 "$repo_root/backend/nft-setup.sh" >/dev/null
table_installed=1
echo "Experimental synchronous UDP ready: uid=$EXL_USER_UID; TCP scope=$TEST_DEST; UDP scope=$UDP_TEST_DEST"
echo "exitlag-netd pid=$netd_pid  log=$log"
runtime_guard_wait "$netd_pid" "$duration"
