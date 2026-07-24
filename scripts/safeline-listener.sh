#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-check}
SAFELINE_DIR=${SAFELINE_DIR:-/data/safeline}
UPSTREAM_PORT=${UPSTREAM_PORT:-10443}
CONTAINER=${SAFELINE_CONTAINER:-safeline-tengine}
SITE_FILE=${SAFELINE_SITE_FILE:-}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

if [[ -z "$SITE_FILE" ]]; then
    mapfile -t candidates < <(grep -lE "listen +(0\.0\.0\.0|127\.0\.0\.1):${UPSTREAM_PORT} +default_server" "$SAFELINE_DIR"/resources/nginx/sites-enabled/IF_* 2>/dev/null || true)
    ((${#candidates[@]} == 1)) || die "expected one SafeLine HTTP site on ${UPSTREAM_PORT}; found ${#candidates[@]}. First change the site port in the SafeLine console, then retry. Set SAFELINE_SITE_FILE only when multiple sites intentionally use this port."
    SITE_FILE=${candidates[0]}
fi

case "$ACTION" in
  check)
    grep -nE "listen +(0\.0\.0\.0|127\.0\.0\.1):${UPSTREAM_PORT} +default_server" "$SITE_FILE" || die "listener not found in $SITE_FILE"
    ;;
  apply)
    [[ ${EUID} -eq 0 ]] || die "apply must run as root"
    backup_dir="$SAFELINE_DIR/backups/sentinel/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$backup_dir"
    cp -a "$SITE_FILE" "$backup_dir/"
    sed -i -E "s/listen +0\.0\.0\.0:${UPSTREAM_PORT} +default_server/listen 127.0.0.1:${UPSTREAM_PORT} default_server/" "$SITE_FILE"
    grep -qE "listen +127\.0\.0\.1:${UPSTREAM_PORT} +default_server" "$SITE_FILE" || die "listener rewrite failed"
    docker exec "$CONTAINER" nginx -t
    docker exec "$CONTAINER" nginx -s reload
    printf 'Applied. Backup: %s/%s\n' "$backup_dir" "$(basename "$SITE_FILE")"
    ;;
  restore)
    backup=${2:-}
    [[ ${EUID} -eq 0 ]] || die "restore must run as root"
    [[ -f "$backup" ]] || die "usage: $0 restore /absolute/path/to/IF_backup"
    cp -a "$backup" "$SITE_FILE"
    docker exec "$CONTAINER" nginx -t
    docker exec "$CONTAINER" nginx -s reload
    ;;
  *) die "usage: $0 check|apply|restore [backup-file]" ;;
esac
