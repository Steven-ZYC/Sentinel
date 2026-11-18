#!/usr/bin/env bash
# Optional systemd runtime guard for any DNS provider; no Tailscale dependency.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'ERROR: run with sudo' >&2; exit 1; }
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ $PROJECT_DIR != *$'\n'* && $PROJECT_DIR != *'"'* && $PROJECT_DIR != *'\\'* && $PROJECT_DIR != *'%'* ]] || { echo 'ERROR: unsupported project path' >&2; exit 1; }
python3 "$PROJECT_DIR/scripts/runtime_guard.py" check-public --project "$PROJECT_DIR"
bash "$PROJECT_DIR/scripts/install-guard-code.sh"
install -d -m 0755 /usr/local/libexec/sentinel
install -d -m 0700 /etc/sentinel
install -m 0755 "$PROJECT_DIR/scripts/sentinel-runtime-guard.sh" /usr/local/libexec/sentinel/sentinel-runtime-guard
sentinel_env_tmp=$(mktemp /etc/sentinel/.runtime-env.XXXXXX)
trap 'rm -f -- "$sentinel_env_tmp"' EXIT
printf 'SENTINEL_PROJECT_DIR="%s"\n' "$PROJECT_DIR" > "$sentinel_env_tmp"
chmod 0600 "$sentinel_env_tmp"
mv "$sentinel_env_tmp" /etc/sentinel/runtime.env
trap - EXIT
install -m 0644 "$PROJECT_DIR/systemd/sentinel-runtime-guard.service" /etc/systemd/system/sentinel-runtime-guard.service
install -m 0644 "$PROJECT_DIR/systemd/sentinel-runtime-guard.timer" /etc/systemd/system/sentinel-runtime-guard.timer
systemctl daemon-reload
systemctl enable --now sentinel-runtime-guard.timer
systemctl start sentinel-runtime-guard.service
echo 'PASS: optional public runtime guard installed; Docker still owns startup and stopped containers remain stopped'
