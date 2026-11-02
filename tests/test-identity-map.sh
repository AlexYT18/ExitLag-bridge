#!/usr/bin/env bash
# Research-only, IPC-only identity translation test.  It does not create an
# nftables table, bind NFQUEUE, or send game traffic.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
port="${EXL_TEST_PORT:-51901}"
helper_pid=""
mapped_pid=""
spoof_pid=""
argv0_pid=""

cleanup() {
    local result=$?
    set +e
    if (( result != 0 )); then
        artifact_dir="$repo_root/runtime/logs/identity-failure-$$"
        mkdir -p "$artifact_dir"
        for logfile in helper.log no-map.log rejected.log; do
            if [[ -f "$work/$logfile" ]]; then
                cp "$work/$logfile" "$artifact_dir/$logfile"
                printf '\n--- synthetic identity fixture: %s ---\n' "$logfile" >&2
                cat "$work/$logfile" >&2
            fi
        done
        echo "Synthetic failure logs retained: $artifact_dir" >&2
    fi
    [[ -n "$helper_pid" ]] && kill "$helper_pid" 2>/dev/null
    [[ -n "$mapped_pid" ]] && kill "$mapped_pid" 2>/dev/null
    [[ -n "$spoof_pid" ]] && kill "$spoof_pid" 2>/dev/null
    [[ -n "$argv0_pid" ]] && kill "$argv0_pid" 2>/dev/null
    [[ -n "$helper_pid" ]] && wait "$helper_pid" 2>/dev/null
    [[ -n "$mapped_pid" ]] && wait "$mapped_pid" 2>/dev/null
    [[ -n "$spoof_pid" ]] && wait "$spoof_pid" 2>/dev/null
    [[ -n "$argv0_pid" ]] && wait "$argv0_pid" 2>/dev/null
    rm -r -- "$work"
}
trap cleanup EXIT

sleep_exe="$(readlink -f "$(command -v sleep)")"
python_exe="$(readlink -f "$(command -v python3)")"
windows_path='G:\World of Warcraft\_classic_era_\WoWClassic.exe'
ln -s "$sleep_exe" "$work/native-game"
printf '%s\t%s\n' "$work/native-game" "$windows_path" >"$work/identity.map"
mkdir "$work/prefix with spaces" "$work/other prefix"
ln -s "$work/prefix with spaces" "$work/prefix alias"
cp "$sleep_exe" "$work/approved runtime"
cp "$sleep_exe" "$work/other approved runtime"
cp "$sleep_exe" "$work/unapproved runtime"
ln -s "$work/approved runtime" "$work/runtime alias"
prefix_windows='C:\Games\Prefix\game.exe'
printf 'wineprefix:%s\t%s\t%s\n' "$work/prefix with spaces" "$prefix_windows" \
    "$work/runtime alias" >>"$work/identity.map"
printf 'wineprefix:%s\t%s\t%s\n' "$work/prefix with spaces" "$prefix_windows" \
    "$work/other approved runtime" >>"$work/identity.map"

sleep 30 & mapped_pid=$!
# Negative control: the old researchd test could smuggle this .exe-looking
# argument through argv. Strict mapping mode must report python itself.
python3 -c 'import time; time.sleep(30)' "$windows_path" "$sleep_exe" & spoof_pid=$!
# argv[0] is no stronger proof than any later argument.
bash -c 'exec -a "$1" "$2" -c "import time; time.sleep(30)"' \
    fixture "$sleep_exe" "$python_exe" & argv0_pid=$!
true & exited_pid=$!; wait "$exited_pid"

"$repo_root/backend/exitlag-netd" --no-queue --port "$port" --token-file "$work/token" --allow-any-pid-resolve \
    --identity-map "$work/identity.map" --log "$work/helper.log" &
helper_pid=$!
for _ in $(seq 1 100); do
    grep -q 'listening for shim' "$work/helper.log" 2>/dev/null && break
    kill -0 "$helper_pid" 2>/dev/null || { cat "$work/helper.log"; exit 1; }
    sleep 0.02
done

python3 - "$port" "$mapped_pid" "$spoof_pid" "$windows_path" "$python_exe" "$work/token" \
    "$argv0_pid" "$exited_pid" "$work" "$prefix_windows" <<'PY'
import binascii
import os
from pathlib import Path
import socket, struct, sys
import subprocess
import time

port, mapped_pid, spoof_pid = map(int, sys.argv[1:4])
expected_mapped, expected_spoof = sys.argv[4:6]
# The helper now requires this session's token in the handshake.
TOKEN = binascii.unhexlify(open(sys.argv[6]).read().strip())
MAGIC = 0x314C5845

def frame(kind, payload):
    return struct.pack("<IHHI", MAGIC, kind, 0, len(payload)) + payload

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data

def receive(sock):
    magic, kind, flags, length = struct.unpack("<IHHI", recv_exact(sock, 12))
    if magic != MAGIC:
        raise RuntimeError("bad magic")
    return kind, recv_exact(sock, length)

def receive_reply(sock, expected_kind):
    while True:
        kind, payload = receive(sock)
        if kind == 0x03 and not payload:
            sock.sendall(frame(0x04, b""))
            continue
        if kind != expected_kind:
            raise RuntimeError(f"unexpected reply {kind:#x}")
        return payload

def resolve(sock, tag, pid):
    sock.sendall(frame(0x20, struct.pack("<QII", tag, pid, 0)))
    payload = receive_reply(sock, 0x21)
    reply_tag, length, reserved = struct.unpack("<QII", payload[:16])
    if reply_tag != tag or reserved != 0:
        raise RuntimeError("malformed resolve reply")
    return payload[16:16 + length].decode("utf-8")

def fixture_ready(pid, expected_exe, prefix=None):
    # Popen's CLOEXEC error pipe may close before procfs exposes the new
    # executable's environment. Establish the fixture before testing policy.
    deadline = time.monotonic() + 5
    actual_exe, env = None, []
    while time.monotonic() < deadline:
        try:
            actual_exe = os.readlink(f"/proc/{pid}/exe")
            env = Path(f"/proc/{pid}/environ").read_bytes().split(b'\0')
        except OSError:
            pass
        if actual_exe == str(expected_exe) and (prefix is None or b'WINEPREFIX=' + os.fsencode(prefix) in env):
            return
        time.sleep(0.005)
    raise RuntimeError(f"fixture did not reach expected exec/env: pid={pid}, exe={actual_exe!r}, "
                       f"prefix_present={any(e.startswith(b'WINEPREFIX=') for e in env)}")

with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(frame(1, struct.pack("<IIQ", 3, 9999, 0) + TOKEN))
    payload = receive_reply(sock, 2)
    fixture_ready(mapped_pid, os.path.realpath(Path(sys.argv[9]) / 'native-game'))
    fixture_ready(spoof_pid, expected_spoof)
    fixture_ready(int(sys.argv[7]), expected_spoof)
    translated = resolve(sock, 1, mapped_pid)
    genuine = resolve(sock, 2, spoof_pid)
    argv0 = resolve(sock, 3, int(sys.argv[7]))
    exited = resolve(sock, 4, int(sys.argv[8]))
    work = Path(sys.argv[9])
    prefix_windows = sys.argv[10]
    # These copied ELF sleepers are explicitly synthetic owner executables.
    # This verifies executable+prefix policy, not Wine/game compatibility.
    cases = [
        (work / "approved runtime", work / "prefix alias", prefix_windows),
        (work / "other approved runtime", work / "prefix with spaces", prefix_windows),
        (work / "unapproved runtime", work / "prefix with spaces", str(work / "unapproved runtime")),
        (work / "approved runtime", work / "other prefix", str(work / "approved runtime")),
        (work / "approved runtime", None, str(work / "approved runtime")),
        (work / "approved runtime", Path("relative-prefix"), str(work / "approved runtime")),
    ]
    for tag, (owner, prefix, expected) in enumerate(cases, 5):
        env = os.environ.copy()
        env.pop("WINEPREFIX", None)
        if prefix is not None:
            env["WINEPREFIX"] = str(prefix)
        proc = subprocess.Popen([str(owner), "30"], env=env)
        try:
            fixture_ready(proc.pid, owner, prefix)
            actual = resolve(sock, tag, proc.pid)
            if actual != expected:
                raise SystemExit(f"owner/prefix policy mismatch: {owner!s} -> {actual!r}")
        finally:
            proc.terminate()
            proc.wait(timeout=5)

print(f"mapped={translated}")
print(f"negative={genuine}")
if translated != expected_mapped:
    raise SystemExit(f"mapped identity mismatch: {translated!r}")
if genuine != expected_spoof:
    raise SystemExit(f"strict negative mismatch: {genuine!r}")
if argv0 != expected_spoof:
    raise SystemExit(f"argv[0] impersonation was accepted: {argv0!r}")
if exited:
    raise SystemExit(f"exited process resolved unexpectedly: {exited!r}")
PY

grep -q "resolve pid=$mapped_pid identity=translated" "$work/helper.log"
grep -q "resolve pid=$spoof_pid identity=genuine" "$work/helper.log"
echo "PASS: canonical native identity translated through configured symlink"
echo "PASS: Windows-looking, canonical source and argv[0] spoofs rejected"
echo "PASS: exited process is unresolved"
echo "PASS: prefix scope requires exact approved owner and canonical prefix"
echo "PASS: unapproved owner, wrong prefix and absent prefix remain genuine"

# A map source is authorization. Reject old argv-only forms before listening,
# rather than accepting an entry that can be impersonated by every process.
for source in game.exe has.exe.trailing; do
    printf '%s\t%s\n' "$source" "$windows_path" >"$work/unsafe.map"
    : >"$work/rejected.log"
    if "$repo_root/backend/exitlag-netd" --no-queue --port "$port" \
        --token-file "$work/rejected.token" --identity-map "$work/unsafe.map" \
        --log "$work/rejected.log"; then
        echo "FAIL: unsafe argv-only map was accepted" >&2
        exit 1
    fi
    grep -q 'argv-only identities are unsafe and unsupported' "$work/rejected.log"
done
echo "PASS: argv-only map sources fail closed with migration diagnostic"

reject_map() {
    local label="$1" pattern="$2"
    : >"$work/rejected.log"
    if "$repo_root/backend/exitlag-netd" --no-queue --port "$port" \
        --token-file "$work/rejected.token" --identity-map "$work/unsafe.map" \
        --log "$work/rejected.log"; then
        echo "FAIL: $label map was accepted" >&2
        exit 1
    fi
    grep -q "$pattern" "$work/rejected.log"
    echo "PASS: $label rejected"
}
printf 'wineprefix:%s\t%s\n' "$work/prefix with spaces" "$prefix_windows" >"$work/unsafe.map"
reject_map 'legacy prefix-only authorization' 'requires OWNER_EXE third column'
for owner in relative-runtime "$work/missing-runtime" "$work/prefix with spaces"; do
    printf 'wineprefix:%s\t%s\t%s\n' "$work/prefix with spaces" "$prefix_windows" "$owner" >"$work/unsafe.map"
    reject_map 'invalid prefix owner' 'OWNER_EXE must resolve to an existing executable file'
done
printf 'not executable\n' >"$work/non-executable"
printf 'wineprefix:%s\t%s\t%s\n' "$work/prefix with spaces" "$prefix_windows" "$work/non-executable" >"$work/unsafe.map"
reject_map 'non-executable prefix owner' 'OWNER_EXE must resolve to an existing executable file'
printf '%s\t%s\t%s\n' "$sleep_exe" "$windows_path" "$sleep_exe" >"$work/unsafe.map"
reject_map 'unexpected native owner column' 'native mapping must have exactly two columns'
printf 'wineprefix:%s\t%s\t%s\n' "$work/prefix with spaces" "$prefix_windows" "$work/runtime alias" >"$work/unsafe.map"
printf 'wineprefix:%s\t%s\t%s\n' "$work/prefix alias" "$prefix_windows" "$work/approved runtime" >>"$work/unsafe.map"
reject_map 'duplicate canonical prefix-owner key' 'duplicate source'

# No-map mode must also use the real executable, never Windows-looking argv.
kill "$helper_pid"
wait "$helper_pid"
helper_pid=""
"$repo_root/backend/exitlag-netd" --no-queue --port "$port" --token-file "$work/no-map.token" \
    --allow-any-pid-resolve --log "$work/no-map.log" &
helper_pid=$!
for _ in $(seq 1 100); do
    grep -q 'listening for shim' "$work/no-map.log" 2>/dev/null && break
    kill -0 "$helper_pid" 2>/dev/null || { cat "$work/no-map.log"; exit 1; }
    sleep 0.02
done
python3 - "$port" "$work/no-map.token" "$python_exe" "$windows_path" <<'PY'
import binascii, socket, struct, subprocess, sys
magic = 0x314c5845
def frame(kind, payload):
    return struct.pack('<IHHI', magic, kind, 0, len(payload)) + payload
def exact(s, count):
    data = b''
    while len(data) < count:
        part = s.recv(count - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data += part
    return data
def expect(s, want):
    while True:
        got_magic, kind, flags, length = struct.unpack('<IHHI', exact(s, 12))
        assert got_magic == magic and flags == 0
        payload = exact(s, length)
        if kind == 3:
            s.sendall(frame(4, b'')); continue
        assert kind == want
        return payload
token = binascii.unhexlify(open(sys.argv[2]).read().strip())
proc = subprocess.Popen([sys.argv[3], '-c', 'import time; time.sleep(30)', sys.argv[4]])
try:
    with socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=5) as s:
        s.sendall(frame(1, struct.pack('<IIQ', 3, 9999, 0) + token))
        expect(s, 2)
        s.sendall(frame(0x20, struct.pack('<QII', 1, proc.pid, 0)))
        payload = expect(s, 0x21)
        tag, length, reserved = struct.unpack('<QII', payload[:16])
        assert tag == 1 and reserved == 0
        actual = payload[16:16 + length].decode()
        assert actual == sys.argv[3], f'no-map argv spoof accepted: {actual!r}'
finally:
    proc.terminate(); proc.wait(timeout=5)
print('PASS: no-map identity resolution rejects Windows-looking argv spoof')
PY
