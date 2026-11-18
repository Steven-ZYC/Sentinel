#!/usr/bin/env bash

# Install the upgrade guard only after SafeLine management is loopback-only.

set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: run this script with sudo" >&2
    exit 1
fi

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GUARD_SOURCE="$PROJECT_DIR/scripts/tailscale-sentinel-guard.sh"
SERVE_UNIT_SOURCE="$PROJECT_DIR/systemd/sentinel-tailscale-serve.service"
CHECK_UNIT_SOURCE="$PROJECT_DIR/systemd/sentinel-tailscale-guard.service"
TIMER_UNIT_SOURCE="$PROJECT_DIR/systemd/sentinel-tailscale-guard.timer"
INSTALL_DIR=/usr/local/libexec/sentinel
BACKUP_DIR=/etc/sentinel/tailscale

for path in "$GUARD_SOURCE" "$SERVE_UNIT_SOURCE" "$CHECK_UNIT_SOURCE" "$TIMER_UNIT_SOURCE"; do
    [[ -f $path ]] || { echo "error: required source file is missing: $path" >&2; exit 1; }
done

# This refuses installation if 9443 is public, rather than silently treating
# Tailscale Serve as a substitute for a correct SafeLine management bind.
SENTINEL_PROJECT_DIR="$PROJECT_DIR" "$GUARD_SOURCE" check
bash "$PROJECT_DIR/scripts/install-guard-code.sh"

install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$GUARD_SOURCE" "$INSTALL_DIR/tailscale-sentinel-guard"
install -d -m 0700 "$BACKUP_DIR"
[[ $PROJECT_DIR != *$'\n'* && $PROJECT_DIR != *'"'* && $PROJECT_DIR != *'\\'* && $PROJECT_DIR != *'%'* ]] || { echo 'error: unsupported project path' >&2; exit 1; }
guard_env=$(mktemp /etc/sentinel/.guard-env.XXXXXX)
printf 'SENTINEL_PROJECT_DIR="%s"\n' "$PROJECT_DIR" > "$guard_env"
chmod 0600 "$guard_env"
mv "$guard_env" /etc/sentinel/guard.env

backup="$BACKUP_DIR/serve-status-$(date -u +%Y%m%dT%H%M%SZ).json"
temporary=$(mktemp "$BACKUP_DIR/.serve-status.XXXXXX")
trap 'rm -f "$temporary"' EXIT
/usr/bin/tailscale serve status --json > "$temporary"
[[ -s $temporary ]] || { echo "error: Tailscale Serve status backup is empty" >&2; exit 1; }
chmod 0600 "$temporary"
mv "$temporary" "$backup"
trap - EXIT

install -m 0644 "$SERVE_UNIT_SOURCE" /etc/systemd/system/sentinel-tailscale-serve.service
install -m 0644 "$CHECK_UNIT_SOURCE" /etc/systemd/system/sentinel-tailscale-guard.service
install -m 0644 "$TIMER_UNIT_SOURCE" /etc/systemd/system/sentinel-tailscale-guard.timer

systemctl daemon-reload
systemctl enable sentinel-tailscale-serve.service
systemctl enable --now sentinel-tailscale-guard.timer
systemctl start sentinel-tailscale-serve.service
systemctl start sentinel-tailscale-guard.service

echo "installed Tailscale/Sentinel upgrade guard"
echo "Serve backup: $backup"
systemctl --no-pager --full status sentinel-tailscale-serve.service sentinel-tailscale-guard.timer
