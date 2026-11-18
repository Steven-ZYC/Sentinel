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

python3 scripts/security_checks.py upstreams
pass "every active IPv4/IPv6 business listener is loopback-only"
python3 scripts/security_checks.py certificates
pass "certificate permissions, expiry, domain coverage and key matching are valid"

python3 scripts/deploy_proxy.py --check-only
pass "candidate, assigned ingress IPs and actual listener owners validated; running revision was not changed"
