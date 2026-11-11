#!/usr/bin/env bash
# Account-free source checks; never enters netfilter or runs the vendor client.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$repo_root/tests/cloud_checks.py" "$@"
