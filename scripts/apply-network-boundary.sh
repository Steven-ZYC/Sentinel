#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: run this script with sudo" >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")
SAFELINE_DIR=/data/safeline
SAFELINE_ENV="$SAFELINE_DIR/.env"
SAFELINE_REALIP="$SAFELINE_DIR/resources/nginx/conf.d/_sentinel_realip.conf"
CF_REALIP="$PROJECT_DIR/nginx/cloudflare-realip.conf"
PROJECT_ENV="$PROJECT_DIR/.env"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="/root/sentinel-boundary-$STAMP"
ROLLBACK_SCRIPT="$BACKUP_DIR/rollback.sh"
ROLLBACK_UNIT=sentinel-boundary-rollback
APPLY_STARTED=0
MANAGEMENT_URL=${MANAGEMENT_URL:-}
MANAGEMENT_INTERFACE=${MANAGEMENT_INTERFACE:-tailscale0}

wait_for_url() {
    local url=$1
    shift
    local attempt

    for attempt in {1..45}; do
        if curl --fail --silent --show-error "$@" "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done

    echo "error: service did not become ready within 90 seconds: $url" >&2
    return 1
}

for command in curl docker grep install ip ss systemctl tar ufw; do
    command -v "$command" >/dev/null || {
        echo "error: required command not found: $command" >&2
        exit 1
    }
done

[[ -f "$SAFELINE_ENV" ]] || {
    echo "error: SafeLine environment file not found: $SAFELINE_ENV" >&2
    exit 1
}
[[ -f "$CF_REALIP" ]] || {
    echo "error: Cloudflare real-IP file not found: $CF_REALIP" >&2
    exit 1
}
[[ -f "$PROJECT_ENV" ]] || {
    echo "error: Sentinel environment file not found: $PROJECT_ENV" >&2
    exit 1
}
[[ -f "$PROJECT_DIR/safeline/sentinel-realip.conf" ]] || {
    echo "error: SafeLine real-IP source file is missing" >&2
    exit 1
}

ip link show "$MANAGEMENT_INTERFACE" >/dev/null 2>&1 || {
    echo "error: $MANAGEMENT_INTERFACE is unavailable; refusing to change management access" >&2
    exit 1
}

MANAGEMENT_IP=$(ip -4 -o addr show dev "$MANAGEMENT_INTERFACE" | awk 'NR == 1 {sub(/\/.*/, "", $4); print $4}')
[[ -n $MANAGEMENT_IP ]] || {
    echo "error: $MANAGEMENT_INTERFACE has no IPv4 address" >&2
    exit 1
}
MANAGEMENT_USER=${MANAGEMENT_USER:-${SUDO_USER:-admin-user}}
PUBLIC_DOMAIN=$("$PROJECT_DIR/scripts/render-sites.py" --list-upstreams | awk -F '\t' 'NR == 1 {print $1}')
[[ -n $PUBLIC_DOMAIN ]] || {
    echo "error: sites.json has no proxy site for the Sentinel health check" >&2
    exit 1
}

if ! ss -Htn state established '( sport = :22 )' | grep -Fq "$MANAGEMENT_IP:22"; then
    echo "error: no active SSH session over $MANAGEMENT_INTERFACE ($MANAGEMENT_IP)" >&2
    echo "connect through the management network before retrying" >&2
    exit 1
fi

if grep -Eq 'set_real_ip_from[[:space:]]+(0\.0\.0\.0/0|::/0)' "$CF_REALIP"; then
    echo "error: Cloudflare trust file contains a trust-all network" >&2
    exit 1
fi

CF_COUNT=$(grep -Ec '^set_real_ip_from[[:space:]]+' "$CF_REALIP")
if [[ $CF_COUNT -lt 20 ]]; then
    echo "error: Cloudflare trust file is unexpectedly short ($CF_COUNT ranges)" >&2
    exit 1
fi

mkdir -m 0700 "$BACKUP_DIR"
cp -a "$SAFELINE_ENV" "$BACKUP_DIR/safeline.env"
tar -C / -cpf "$BACKUP_DIR/ufw.tar" etc/ufw
if [[ -f "$SAFELINE_REALIP" ]]; then
    cp -a "$SAFELINE_REALIP" "$BACKUP_DIR/safeline-realip.conf"
    touch "$BACKUP_DIR/had-safeline-realip"
fi

cat >"$ROLLBACK_SCRIPT" <<EOF
#!/usr/bin/env bash
set -u
cp -a "$BACKUP_DIR/safeline.env" "$SAFELINE_ENV"
if [[ -f "$BACKUP_DIR/had-safeline-realip" ]]; then
    cp -a "$BACKUP_DIR/safeline-realip.conf" "$SAFELINE_REALIP"
else
    rm -f "$SAFELINE_REALIP"
fi
tar -C / -xpf "$BACKUP_DIR/ufw.tar"
(cd "$SAFELINE_DIR" && docker compose up -d mgt) || true
docker exec safeline-tengine nginx -t && docker exec safeline-tengine nginx -s reload || true
ufw --force reload || ufw --force enable || true
EOF
chmod 0700 "$ROLLBACK_SCRIPT"

rollback_on_error() {
    local status=$?
    if [[ $APPLY_STARTED -eq 1 ]]; then
        echo "error: deployment failed; restoring previous management and firewall configuration" >&2
        /bin/bash "$ROLLBACK_SCRIPT" || true
    fi
    exit "$status"
}
trap rollback_on_error ERR

echo "[1/7] validating Sentinel configuration"
(cd "$PROJECT_DIR" && ./scripts/render-sites.py --check --check-certificates)
(cd "$PROJECT_DIR" && docker compose config --quiet)
(cd "$PROJECT_DIR" && docker compose run --rm --no-deps proxy nginx -t)

echo "[2/7] installing SafeLine loopback trust"
APPLY_STARTED=1
install -o root -g root -m 0644 \
    "$PROJECT_DIR/safeline/sentinel-realip.conf" "$SAFELINE_REALIP"
docker exec safeline-tengine nginx -t
docker exec safeline-tengine nginx -s reload

echo "[3/7] binding SafeLine management to loopback"
sed -i -E 's|^MGT_PORT=.*$|MGT_PORT=127.0.0.1:9443|' "$SAFELINE_ENV"
(cd "$SAFELINE_DIR" && docker compose up -d mgt)
wait_for_url https://127.0.0.1:9443/api/open/health --insecure

echo "[4/7] recreating Sentinel with trusted Cloudflare ranges"
(cd "$PROJECT_DIR" && docker compose up -d)
(cd "$PROJECT_DIR" && docker compose exec -T proxy nginx -t)
wait_for_url "https://$PUBLIC_DOMAIN/.sentinel/health" --insecure \
    --resolve "$PUBLIC_DOMAIN:443:127.0.0.1"

echo "[5/7] scheduling automatic rollback in three minutes"
systemctl stop "$ROLLBACK_UNIT.timer" "$ROLLBACK_UNIT.service" 2>/dev/null || true
systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active=3m \
    /bin/bash "$ROLLBACK_SCRIPT"

echo "[6/7] replacing UFW rules with the documented boundary"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# Preserve authenticated Tailscale connectivity and direct peer negotiation.
ufw allow in on "$MANAGEMENT_INTERFACE" proto tcp to any port 22 comment 'SSH via management network'
ufw allow in on eth0 proto udp to any port 41641 comment 'Tailscale direct UDP'

while read -r cidr; do
    [[ -n $cidr ]] || continue
    ufw allow in on eth0 proto tcp from "$cidr" to any port 80,443 \
        comment 'Cloudflare web'
done < <(awk '/^set_real_ip_from/ { gsub(/;/, "", $2); print $2 }' "$CF_REALIP")

ufw --force enable
ufw status verbose

echo "[7/7] checking services after firewall activation"
wait_for_url https://127.0.0.1:9443/api/open/health --insecure
wait_for_url "https://$PUBLIC_DOMAIN/.sentinel/health"
if [[ -n $MANAGEMENT_URL ]]; then
    wait_for_url "$MANAGEMENT_URL"
fi

echo
echo "Boundary is active, but an automatic rollback is still armed."
echo "Open a SECOND terminal and verify:"
echo "  ssh $MANAGEMENT_USER@$MANAGEMENT_IP"
if [[ -n $MANAGEMENT_URL ]]; then
    echo "Then authenticate through Cloudflare Access and test:"
    echo "  $MANAGEMENT_URL"
else
    echo "Then test a temporary management tunnel:"
    echo "  ssh -N -L 9443:127.0.0.1:9443 $MANAGEMENT_USER@$MANAGEMENT_IP"
    echo "  browse to https://127.0.0.1:9443"
fi
echo
read -r -t 150 -p "Type CONFIRM after both tests succeed: " confirmation || true

if [[ ${confirmation:-} != CONFIRM ]]; then
    echo "confirmation not received; automatic rollback remains scheduled" >&2
    echo "backup: $BACKUP_DIR" >&2
    exit 2
fi

systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
systemctl reset-failed "$ROLLBACK_UNIT.service" 2>/dev/null || true
trap - ERR

echo "network boundary confirmed"
echo "backup: $BACKUP_DIR"
