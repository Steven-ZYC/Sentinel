#!/usr/bin/env bash
set -Eeuo pipefail
PROJECT_DIR=${SENTINEL_PROJECT_DIR:?set SENTINEL_PROJECT_DIR in /etc/sentinel/runtime.env}
GUARD_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ -f $GUARD_DIR/scripts/runtime_guard.py ]] || { echo 'ERROR: installed root-owned guard snapshot missing; reinstall guard' >&2; exit 1; }
exec /usr/bin/python3 -E -s "$GUARD_DIR/scripts/runtime_guard.py" "${1:-check-public}" --project "$PROJECT_DIR"
