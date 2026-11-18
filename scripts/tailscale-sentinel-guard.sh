#!/usr/bin/env bash
# Optional Tailscale guard. Never rewrite management bindings automatically.
set -Eeuo pipefail

ACTION=${1:-check}
PROJECT_DIR=${SENTINEL_PROJECT_DIR:-$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
TAILSCALE_BIN=${TAILSCALE_BIN:-/usr/bin/tailscale}
DOCKER_BIN=${DOCKER_BIN:-/usr/bin/docker}
export TAILSCALE_BIN DOCKER_BIN
MANAGEMENT_PORT=${SENTINEL_MANAGEMENT_PORT:-9443}
SERVE_PORT=${SENTINEL_SERVE_PORT:-443}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    if command -v logger >/dev/null; then logger -t sentinel-tailscale-guard -- "$*" || true; fi
    exit 1
}

[[ $MANAGEMENT_PORT == 9443 && $SERVE_PORT == 443 ]] || fail "only the documented 443 -> local 9443 policy is supported"
[[ ${SENTINEL_ENV_FILE:-$PROJECT_DIR/.env} == "$PROJECT_DIR/.env" ]] || fail "configure the environment inside SENTINEL_PROJECT_DIR"
[[ -f $PROJECT_DIR/scripts/security_checks.py ]] || fail "set SENTINEL_PROJECT_DIR to the installed project"
GUARD_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $GUARD_DIR == "$PROJECT_DIR/scripts" ]]; then
    RUNTIME_SOURCE="$PROJECT_DIR/scripts/runtime_guard.py"
else
    RUNTIME_SOURCE="$GUARD_DIR/scripts/runtime_guard.py"
fi
[[ -f $RUNTIME_SOURCE ]] || fail "installed root-owned runtime snapshot missing; reinstall guard"

case "$ACTION" in
    check)
        exec /usr/bin/python3 -E -s "$RUNTIME_SOURCE" check-tailnet --project "$PROJECT_DIR"
        ;;
    ensure)
        [[ $EUID -eq 0 ]] || fail "ensure requires root"
        export TAILSCALE_BIN DOCKER_BIN
        exec /usr/bin/python3 -E -s "$RUNTIME_SOURCE" ensure-tailnet --project "$PROJECT_DIR"
        ;;
    *) fail "usage: $0 check|ensure" ;;
esac
