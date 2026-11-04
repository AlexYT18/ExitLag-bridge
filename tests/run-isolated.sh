#!/usr/bin/env bash
# Level 2 only: disposable user/network/PID/mount namespaces and local peers.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

skip() { printf 'SKIP: %s\n' "$*" >&2; exit 77; }

if [[ ${1:-} != --inside ]]; then
    [[ $# == 0 ]] || { echo 'Usage: tests/run-isolated.sh' >&2; exit 2; }
    for tool in unshare ip mount nft python3; do
        command -v "$tool" >/dev/null || skip "missing Level 2 dependency: $tool"
    done
    host_net="$(readlink /proc/self/ns/net)"
    host_pid="$(readlink /proc/self/ns/pid)"
    user_options=()
    [[ $EUID == 0 ]] || user_options=(--user --map-root-user)
    probe_output="$(unshare "${user_options[@]}" --net --pid --mount --fork --mount-proc \
        sh -c 'ip link set lo up && nft list tables' 2>&1)" || skip "namespace/NFQUEUE prerequisites unavailable: $probe_output"
    exec unshare "${user_options[@]}" --net --pid --mount --fork --mount-proc \
        "$repo_root/tests/run-isolated.sh" --inside "$host_net" "$host_pid"
fi

[[ $# == 3 ]] || { echo 'Invalid isolated invocation' >&2; exit 2; }
host_net="$2"; host_pid="$3"
[[ $EUID == 0 && "$(readlink /proc/self/ns/net)" != "$host_net" && \
   "$(readlink /proc/self/ns/pid)" != "$host_pid" ]] || skip 'network and PID isolation was not established'
# /run and netns bind mounts exist only in this mount namespace. This also lets
# an unprivileged single-UID user namespace use the production /run paths.
mount --make-rprivate /
mount -t tmpfs -o mode=755,nosuid,nodev tmpfs /run
ip link set lo up
export EXITLAG_TEST_ISOLATED=1
export EXITLAG_TEST_HOST_NETNS="$host_net" EXITLAG_TEST_HOST_PIDNS="$host_pid"

peer=exl-test-peer
server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    ip netns delete "$peer" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$peer"
ip link add exl-host type veth peer name exl-peer
ip link set exl-peer netns "$peer"
ip addr add 192.0.2.1/24 dev exl-host
ip -6 addr add 2001:db8:1::1/64 dev exl-host nodad
ip link set exl-host up
ip netns exec "$peer" ip link set lo up
ip netns exec "$peer" ip addr add 192.0.2.2/24 dev exl-peer
ip netns exec "$peer" ip -6 addr add 2001:db8:1::2/64 dev exl-peer nodad
ip netns exec "$peer" ip link set exl-peer up

ip netns exec "$peer" python3 -u - <<'PY' &
import socket
import threading


def serve(family, address, port):
    with socket.socket(family) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((address, port))
        server.listen(64)
        while True:
            client, _ = server.accept()
            client.close()


threading.Thread(target=serve, args=(socket.AF_INET, "192.0.2.2", 3724), daemon=True).start()
serve(socket.AF_INET6, "2001:db8:1::2", 443)
PY
server_pid=$!
export PROBE_DEST=192.0.2.2 PROBE_PORT=3724 V6_DEST=2001:db8:1::2
python3 - <<'PY'
import socket
import time
for family, address, port in ((socket.AF_INET, '192.0.2.2', 3724),
                              (socket.AF_INET6, '2001:db8:1::2', 443)):
    for attempt in range(50):
        try:
            with socket.socket(family) as probe:
                probe.settimeout(.2)
                probe.connect((address, port))
            break
        except OSError:
            if attempt == 49:
                raise
            time.sleep(.1)
PY
echo 'Level 2: local synthetic peers; separate network, PID and mount namespaces.'
"$repo_root/tests/run-all.sh" system-only
