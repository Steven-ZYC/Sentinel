#!/usr/bin/env bash
# Explicit root installation snapshots code; a timer must not execute a writable checkout.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'ERROR: guard snapshot installation requires root' >&2; exit 1; }
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
INSTALL_DIR=/usr/local/libexec/sentinel
for sentinel_directory in /usr/local /usr/local/libexec "$INSTALL_DIR" "$INSTALL_DIR/scripts" "$INSTALL_DIR/nginx"; do
    if [[ -e $sentinel_directory ]]; then
        [[ ! -L $sentinel_directory && $(stat -c %u "$sentinel_directory") == 0 ]] || { echo "ERROR: untrusted guard installation directory: $sentinel_directory" >&2; exit 1; }
        sentinel_mode=$(stat -c %a "$sentinel_directory")
        (( (8#$sentinel_mode & 0022) == 0 )) || { echo "ERROR: writable guard installation directory: $sentinel_directory" >&2; exit 1; }
    else
        install -d -o root -g root -m 0755 "$sentinel_directory"
    fi
done
install -o root -g root -m 0755 "$PROJECT_DIR/scripts/container-startup-check.sh" "$INSTALL_DIR/container-startup-check.sh"
for sentinel_module in runtime_guard.py listener_boundary.py security_checks.py render-sites.py; do
    install -o root -g root -m 0644 "$PROJECT_DIR/scripts/$sentinel_module" "$INSTALL_DIR/scripts/$sentinel_module"
done
for sentinel_asset in nginx.conf cloudflare-realip.conf; do
    install -o root -g root -m 0644 "$PROJECT_DIR/nginx/$sentinel_asset" "$INSTALL_DIR/nginx/$sentinel_asset"
done
