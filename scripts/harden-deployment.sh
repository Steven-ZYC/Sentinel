#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ $EUID -eq 0 ]] || { echo 'ERROR: run with sudo; production was not modified' >&2; exit 1; }
[[ $# == 0 || ( $# == 1 && $1 == --tailscale ) ]] || { echo 'usage: sudo ./scripts/harden-deployment.sh [--tailscale]' >&2; exit 2; }
if [[ ${1:-} == --tailscale ]]; then
    python3 scripts/security_checks.py management-tailnet
else
    python3 scripts/security_checks.py management
fi
python3 scripts/harden_deployment.py tls
mapfile -t ports < <(python3 scripts/render-sites.py --list-upstreams | cut -f3)
((${#ports[@]} > 0)) || { echo 'ERROR: no validated business ports' >&2; exit 1; }
for port in "${ports[@]}"; do
    UPSTREAM_PORT="$port" bash scripts/safeline-listener.sh apply
done
python3 scripts/harden_deployment.py realip
python3 scripts/harden_deployment.py backups
python3 scripts/deploy_proxy.py
if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
    bash scripts/install-runtime-guard.sh
fi
if [[ ${1:-} == --tailscale ]]; then
    bash scripts/install-tailscale-sentinel-guard.sh
fi
echo 'PASS: local hardening applied. Firewall, public TLS/headers and key rotation need separate verification.'
