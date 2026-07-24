#!/usr/bin/env bash

# Bind SafeLine management to loopback while retaining a private Tailscale
# HTTPS Serve route to https+insecure://localhost:9443.

set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: run this script with sudo" >&2
    exit 1
fi

SAFELINE_DIR=${SAFELINE_DIR:-/data/safeline}
SAFELINE_ENV="$SAFELINE_DIR/.env"
MANAGEMENT_PORT=${MANAGEMENT_PORT:-9443}
MANAGEMENT_URL=${MANAGEMENT_URL:-}
ROLLBACK_UNIT=safeline-management-tailscale-rollback
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="/root/safeline-management-tailscale-$STAMP"
ROLLBACK_SCRIPT="$BACKUP_DIR/rollback.sh"
CHANGED=0

wait_for_url() {
    local url=$1
    local attempt

    for attempt in {1..45}; do
        if curl --fail --silent --show-error --insecure \
            --connect-timeout 5 --max-time 10 "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done

    echo "error: service did not become ready within 90 seconds: $url" >&2
    return 1
}

for command in curl docker grep ip ss systemctl tailscale tar; do
    command -v "$command" >/dev/null || {
        echo "error: required command not found: $command" >&2
        exit 1
    }
done

[[ -f "$SAFELINE_ENV" ]] || {
    echo "error: SafeLine environment file not found: $SAFELINE_ENV" >&2
    exit 1
}

TAILNET_HOST=$(tailscale serve status 2>/dev/null | sed -n 's|^https://\([^ ]*\) (tailnet only).*|\1|p' | head -n 1)
[[ -n $TAILNET_HOST ]] || {
    echo "error: no Tailscale HTTPS Serve hostname is configured" >&2
    echo "enable it first with: sudo tailscale serve --bg https+insecure://localhost:$MANAGEMENT_PORT" >&2
    exit 1
}

SERVE_CONFIG=$(tailscale serve status --json 2>/dev/null)
if ! grep -q '"443"' <<<"$SERVE_CONFIG" || \
   ! grep -q "https+insecure://localhost:$MANAGEMENT_PORT" <<<"$SERVE_CONFIG"; then
    echo "error: Tailscale HTTPS Serve is not forwarding to localhost:$MANAGEMENT_PORT" >&2
    echo "configure it with: sudo tailscale serve --bg https+insecure://localhost:$MANAGEMENT_PORT" >&2
    exit 1
fi

[[ -n $MANAGEMENT_URL ]] || MANAGEMENT_URL="https://$TAILNET_HOST"
wait_for_url "https://127.0.0.1:$MANAGEMENT_PORT/api/open/health"

mkdir -m 0700 "$BACKUP_DIR"
cp -a "$SAFELINE_ENV" "$BACKUP_DIR/safeline.env"

cat >"$ROLLBACK_SCRIPT" <<EOF
#!/usr/bin/env bash
set -u
cp -a "$BACKUP_DIR/safeline.env" "$SAFELINE_ENV"
(cd "$SAFELINE_DIR" && docker compose up -d mgt) || true
EOF
chmod 0700 "$ROLLBACK_SCRIPT"

rollback_on_error() {
    local status=$?
    if [[ $CHANGED -eq 1 ]]; then
        echo "error: change failed; restoring prior SafeLine management binding" >&2
        /bin/bash "$ROLLBACK_SCRIPT" || true
    fi
    exit "$status"
}
trap rollback_on_error ERR

echo "[1/5] confirming Tailscale HTTPS Serve route"
tailscale serve status

echo "[2/5] binding SafeLine management to loopback"
CHANGED=1
sed -i -E "s|^MGT_PORT=.*$|MGT_PORT=127.0.0.1:$MANAGEMENT_PORT|" "$SAFELINE_ENV"
(cd "$SAFELINE_DIR" && docker compose up -d mgt)
wait_for_url "https://127.0.0.1:$MANAGEMENT_PORT/api/open/health"

echo "[3/5] verifying public bind is gone"
if ss -H -ltn "sport = :$MANAGEMENT_PORT" | awk '{print $4}' | \
    grep -Eq "^(0\\.0\\.0\\.0|\[::\]):$MANAGEMENT_PORT$"; then
    echo "error: management port is still publicly bound" >&2
    false
fi
if ! ss -H -ltn "sport = :$MANAGEMENT_PORT" | awk '{print $4}' | \
    grep -qx "127.0.0.1:$MANAGEMENT_PORT"; then
    echo "error: management port is not bound to loopback" >&2
    false
fi

echo "[4/5] verifying local Tailscale Serve configuration"
if ! tailscale serve status --json 2>/dev/null | \
    grep -q "https+insecure://localhost:$MANAGEMENT_PORT"; then
    echo "error: Tailscale HTTPS Serve route changed unexpectedly" >&2
    false
fi

echo "[5/5] scheduling automatic rollback in three minutes"
systemctl stop "$ROLLBACK_UNIT.timer" "$ROLLBACK_UNIT.service" 2>/dev/null || true
systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active=3m \
    /bin/bash "$ROLLBACK_SCRIPT"

echo
echo "SafeLine management is now loopback-only."
echo "From another device in this Tailnet, open:"
echo "  $MANAGEMENT_URL"
echo "Verify the page, /api/open/health, login, event list, and save operations."
echo
read -r -t 150 -p "Type CONFIRM after remote Tailnet access succeeds: " confirmation || true
if [[ ${confirmation:-} != CONFIRM ]]; then
    echo "confirmation not received; automatic rollback remains scheduled" >&2
    echo "backup: $BACKUP_DIR" >&2
    exit 2
fi

systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
systemctl reset-failed "$ROLLBACK_UNIT.service" 2>/dev/null || true
trap - ERR

echo "SafeLine management binding confirmed"
echo "backup: $BACKUP_DIR"
