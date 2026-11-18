#!/usr/bin/env bash
set -euo pipefail
if [[ $# == 0 ]]; then
    [[ -n ${TARGET_URL:-} ]] || { echo "usage: $0 https://app.example.com [--ca-file bundle.pem]" >&2; exit 2; }
    set -- "$TARGET_URL"
fi
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/verify_edge.py" "$@"
