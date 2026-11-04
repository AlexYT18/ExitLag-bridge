#!/usr/bin/env bash
# Cloud-safe real-thread regression for the production lifecycle coordinator.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cxx="${CXX:-c++}"
if ! command -v "$cxx" >/dev/null 2>&1; then
    echo "SKIP: shim lifecycle requires a native C++ compiler (CXX=$cxx)"
    exit 77
fi
flags=(-std=c++11 -Wall -Wextra -Werror -pedantic -O1 -g -pthread)
case "${1:-}" in
    "") ;;
    --sanitize) flags+=("-fsanitize=address,undefined" -fno-omit-frame-pointer) ;;
    *) echo "usage: $0 [--sanitize]" >&2; exit 2 ;;
esac
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
"$cxx" "${flags[@]}" "$repo_root/tests/test-shim-lifecycle.cpp" -o "$work/test-shim-lifecycle"
"$work/test-shim-lifecycle"
