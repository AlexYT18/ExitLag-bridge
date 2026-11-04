#!/usr/bin/env bash
# Install the scoped nftables surface for exitlag-netd.
#
# Everything lives in a dedicated `inet exitlag` table so teardown is a single
# atomic delete and no other firewall state is read or written.
#
# Safety properties:
#   - `queue ... bypass`: if exitlag-netd is not running, the kernel ACCEPTs the
#     packet instead of dropping it. Existing conntrack translations are not
#     removed by queue bypass or table teardown.
#   - the queue runs after conntrack but before destination NAT. The helper can
#     therefore install an exact map element while the SYN is suspended. Only
#     that packet receives the transient priority authorization bit. A stale
#     map alone cannot authorize a new DNAT; conntrack retains existing flows.
#   - only the first SYN of a new, non-DNATed outbound TCP connection is queued,
#     so the steady-state data path is untouched even while the helper runs.
#   - loopback is skipped entirely, which also keeps the shim<->helper channel
#     out of the queue.
#   - by default only traffic to TEST_DEST is queued, so a stray rule cannot
#     affect the whole machine during bring-up. Set TEST_DEST=any to widen it.
set -euo pipefail

QUEUE_NUM="${QUEUE_NUM:-0}"
TEST_DEST="${TEST_DEST:-}"
UDP_QUEUE_NUM="${UDP_QUEUE_NUM:-1}"
UDP_TEST_DEST="${UDP_TEST_DEST:-}"
UDP_TEST_PORT="${UDP_TEST_PORT:-}"
ENABLE_UDP_OBSERVE="${ENABLE_UDP_OBSERVE:-0}"
ENABLE_UDP_STEER="${ENABLE_UDP_STEER:-0}"
ENABLE_UDP_MULTI="${ENABLE_UDP_MULTI:-0}"
user_match=""
if [[ -n "${EXL_USER_UID:-}" ]]; then
    if ! [[ "$EXL_USER_UID" =~ ^[0-9]+$ ]] || (( EXL_USER_UID < 1000 )); then
        echo 'EXL_USER_UID must identify the authorized game user' >&2; exit 2
    fi
    user_match="meta skuid $EXL_USER_UID"
fi

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (needs CAP_NET_ADMIN); re-run with sudo" >&2
    exit 1
fi

if [[ -z "$TEST_DEST" ]]; then
    echo "refusing to install without an explicit scope." >&2
    echo "set TEST_DEST=<ip> to queue only traffic to that host, or TEST_DEST=any" >&2
    exit 2
fi

# Scope selection. Note an `inet` table needs the family-correct matcher:
# `ip daddr` only matches IPv4 and `ip6 daddr` only matches IPv6, while no
# daddr match at all covers both. Getting this wrong silently queues nothing.
if [[ "$TEST_DEST" == "any" ]]; then
    match=""
    echo "WARNING: queuing ALL new outbound TCP connections, both families"
    echo "         (queue ... bypass keeps this fail-open if the helper dies)"
elif [[ "$TEST_DEST" == *:* ]]; then
    match="ip6 daddr $TEST_DEST"
else
    match="ip daddr $TEST_DEST"
fi

udp_chains=""
if [[ "$ENABLE_UDP_OBSERVE" == 1 ]]; then
    if [[ -z "$UDP_TEST_DEST" ]]; then
        echo "refusing UDP observation without UDP_TEST_DEST=<ip|any>." >&2
        exit 2
    fi
    if [[ "$UDP_TEST_DEST" == "any" ]]; then
        udp_out_match=""
        udp_in_match=""
        echo "UDP destination scope is any; any configured port scope still applies"
    elif [[ "$UDP_TEST_DEST" == *:* ]]; then
        udp_out_match="ip6 daddr $UDP_TEST_DEST"
        udp_in_match="ip6 saddr $UDP_TEST_DEST"
    else
        udp_out_match="ip daddr $UDP_TEST_DEST"
        udp_in_match="ip saddr $UDP_TEST_DEST"
    fi
    if [[ -n "$UDP_TEST_PORT" ]]; then
        # A single port, or an inclusive range "LOW-HIGH". Games that pick a
        # server port out of a block (Dota 2 uses ~27000-27100) cannot be scoped
        # by one number, and widening to every UDP port would be worse.
        port_ok=0
        if [[ "$UDP_TEST_PORT" =~ ^[0-9]+$ ]] && (( UDP_TEST_PORT >= 1 && UDP_TEST_PORT <= 65535 )); then
            port_ok=1
        elif [[ "$UDP_TEST_PORT" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            low="${BASH_REMATCH[1]}"; high="${BASH_REMATCH[2]}"
            (( low >= 1 && high <= 65535 && low <= high )) && port_ok=1
        fi
        if (( ! port_ok )); then
            echo "UDP_TEST_PORT must be a port (1-65535) or an inclusive range LOW-HIGH" >&2
            exit 2
        fi
        udp_out_match="$udp_out_match udp dport $UDP_TEST_PORT"
        udp_in_match="$udp_in_match udp sport $UDP_TEST_PORT"
    fi
    if [[ "$ENABLE_UDP_STEER" == 1 && "$ENABLE_UDP_MULTI" != 1 && -z "$UDP_TEST_PORT" ]]; then
        echo "refusing UDP steering without an exact UDP_TEST_PORT" >&2
        exit 2
    fi
    udp_reinject_guard=""
    if [[ "$ENABLE_UDP_STEER" == 1 ]]; then
        udp_reinject_guard='meta mark 0x584c0001 counter accept'
    fi
    udp_input_loopback='iifname "lo" accept'
    if [[ "$ENABLE_UDP_MULTI" == 1 ]]; then
        # Native attribution permits local-proxy replies only for a recorded,
        # current-session reverse peer. Other loopback UDP remains untouched.
        udp_input_loopback=""
    fi
    read -r -d '' udp_chains <<NFT_UDP || true

    chain output_udp_observe {
        type filter hook output priority -10; policy accept;
        oifname "lo" accept
        $udp_reinject_guard
        $user_match meta l4proto udp $udp_out_match queue num $UDP_QUEUE_NUM bypass
    }

    chain input_udp_observe {
        type filter hook input priority -10; policy accept;
        $udp_input_loopback
        $udp_reinject_guard
        meta l4proto udp $udp_in_match queue num $UDP_QUEUE_NUM bypass
    }
NFT_UDP
fi

# Pre-flight: the table must not already exist. A leftover table would mean a
# previous run did not tear down, and silently re-adding rules on top of it
# could change behaviour in ways the logs would not explain.
if nft list table inet exitlag >/dev/null 2>&1; then
    echo "table inet exitlag already exists from an earlier run." >&2
    echo "remove it first: backend/nft-teardown.sh" >&2
    exit 3
fi
echo "pre-flight: no pre-existing inet exitlag table"

nft -f - <<NFT
table inet exitlag {
    map tcp_redirect_v4 {
        type ipv4_addr . inet_service . ipv4_addr . inet_service : ipv4_addr . inet_service
        flags timeout
        timeout 10s
    }

    map tcp_redirect_v6 {
        type ipv6_addr . inet_service . ipv6_addr . inet_service : ipv6_addr . inet_service
        flags timeout
        timeout 10s
    }

    chain output_queue {
        type filter hook output priority -150; policy accept;
        # Reserve priority bit31 only on candidate SYNs. Clear before every
        # bypass/early accept, so SO_PRIORITY cannot reuse old authorization.
        # Never modify fwmark: NFQUEUE may reroute before the next hook.
        $user_match meta l4proto tcp tcp flags & (syn|ack) == syn $match meta priority set meta priority & 0x7fffffff
        oifname "lo" accept
        ct status dnat accept
        $user_match meta l4proto tcp tcp flags & (syn|ack) == syn ct state new $match queue num $QUEUE_NUM bypass
    }

    chain tcp_authorized_nat {
        # Consume authorization before map lookup/DNAT and route recalculation.
        meta priority set meta priority & 0x7fffffff
        $user_match meta l4proto tcp dnat ip to ip saddr . tcp sport . ip daddr . tcp dport map @tcp_redirect_v4
        $user_match meta l4proto tcp dnat ip6 to ip6 saddr . tcp sport . ip6 daddr . tcp dport map @tcp_redirect_v6
    }

    chain output_nat {
        # Numeric NF_IP_PRI_NAT_DST also works with Ubuntu 22.04's nft parser,
        # which rejects the dstnat alias for an output hook.
        type nat hook output priority -100; policy accept;
        $user_match meta l4proto tcp tcp flags & (syn|ack) == syn $match meta priority & 0x80000000 != 0 jump tcp_authorized_nat
    }

    chain output_priority_cleanup {
        # NAT chains can be skipped when conntrack already has a binding.
        # Do not leak the internal bit into subsequent QoS/tc processing.
        type filter hook output priority -99; policy accept;
        $user_match meta l4proto tcp tcp flags & (syn|ack) == syn $match meta priority set meta priority & 0x7fffffff
    }
$udp_chains
}
NFT

echo "installed table inet exitlag (queue $QUEUE_NUM, scope: ${TEST_DEST})"
echo "TCP SYN priority bit31 is reserved for transient DNAT authorization; fwmark is unchanged"
if [[ "$ENABLE_UDP_OBSERVE" == 1 ]]; then
    if [[ "$ENABLE_UDP_STEER" == 1 ]]; then
        echo "UDP steering queue $UDP_QUEUE_NUM, scope: ${UDP_TEST_DEST}${UDP_TEST_PORT:+:$UDP_TEST_PORT}; marked replacements bypass the queue"
    else
        echo "UDP observation queue $UDP_QUEUE_NUM, scope: ${UDP_TEST_DEST}${UDP_TEST_PORT:+:$UDP_TEST_PORT}; verdicts remain unchanged"
    fi
fi
nft list table inet exitlag
