#!/usr/bin/env bash
# Native tests for the same freestanding socket-table decoder used by nfapi.dll.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cxx="${CXX:-c++}"
if ! command -v "$cxx" >/dev/null 2>&1; then
    echo "SKIP: shim attribution requires a native C++ compiler (CXX=$cxx)"
    exit 77
fi

flags=(-std=c++11 -Wall -Wextra -Werror -pedantic -O1 -g)
if (( $# > 1 )); then
    echo "usage: $0 [--sanitize]" >&2
    exit 2
fi
case "${1:-}" in
    "") ;;
    --sanitize) flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer) ;;
    *) echo "usage: $0 [--sanitize]" >&2; exit 2 ;;
esac
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
"$cxx" "${flags[@]}" "$repo_root/tests/test-shim-attribution.cpp" -o "$work/test-shim-attribution"
"$work/test-shim-attribution"
