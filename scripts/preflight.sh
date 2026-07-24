#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Steven Zhang

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
pass() { printf 'OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

command -v docker >/dev/null || fail "docker is not installed"
docker compose version >/dev/null || fail "docker compose plugin is not installed"
[[ -f .env ]] || fail "copy .env.example to .env and review every value"
[[ -f sites.json ]] || fail "copy sites.example.json to sites.json and define every site"
[[ -x scripts/render-sites.py ]] || fail "site renderer is not executable"

scripts/render-sites.py --check --check-certificates
pass "site manifest and generated NGINX configuration are current"

while IFS=$'\t' read -r domain upstream_addr upstream_port; do
    if ! ss -H -ltn "sport = :${upstream_port}" | grep -q .; then
        fail "SafeLine is not listening for ${domain} on ${upstream_addr}:${upstream_port}"
    fi
    if ! ss -H -ltn "sport = :${upstream_port}" | awk '{print $4}' | grep -qx "${upstream_addr}:${upstream_port}"; then
        fail "SafeLine ${domain} listener ${upstream_port} is not loopback-only; run safeline-listener.sh apply before deploying Sentinel"
    fi
    pass "SafeLine ${domain} listener is loopback-only (${upstream_addr}:${upstream_port})"
done < <(scripts/render-sites.py --list-upstreams)

while IFS=$'\t' read -r certificate private_key; do
    openssl x509 -in "$certificate" -noout -checkend 604800 >/dev/null || fail "certificate expires within 7 days: $certificate"
done < <(scripts/render-sites.py --list-certificates --check-certificates)
pass "all configured certificates are readable and valid for more than 7 days"

if ss -H -ltn "sport = :80" | grep -q . || ss -H -ltn "sport = :443" | grep -q .; then
    warn "port 80 or 443 is already in use; confirm the listener is the existing Sentinel instance before an in-place update"
fi

docker compose config --quiet
pass "Compose configuration is valid"
docker compose run --rm --no-deps proxy nginx -t
pass "rendered NGINX configuration passes nginx -t"
