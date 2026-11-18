#!/bin/sh
# Docker remains the only startup/restart owner. No daemon is started here.
set -eu

# Candidate validation and explicit reload are not container startup.
for sentinel_argument in "$@"; do
    case "$sentinel_argument" in -t|-T|-s) exec /docker-entrypoint.sh "$@" ;; esac
done

sentinel_current=/etc/nginx/conf.d/current
sentinel_manifest="$sentinel_current/.startup-checksums"
[ -f "$sentinel_manifest" ] || { echo 'ERROR: deploy a checked atomic revision before starting Sentinel' >&2; exit 1; }
sha256sum -c "$sentinel_manifest" >/dev/null || { echo 'ERROR: bootstrap/revision drift; refusing potentially overlapping listeners' >&2; exit 1; }
for sentinel_file in "$sentinel_current"/*.conf; do
    sentinel_hash=$(sha256sum "$sentinel_file")
    grep -Fqx "$sentinel_hash" "$sentinel_manifest" || { echo "ERROR: unexpected included file: $sentinel_file" >&2; exit 1; }
done
nginx -t
command -v ip >/dev/null || { echo 'ERROR: ip is required for explicit-address startup checks' >&2; exit 1; }
sentinel_tailnet_interface=tailscale0
if [ -f "$sentinel_current/.tailscale-interface" ]; then
    IFS= read -r sentinel_tailnet_interface < "$sentinel_current/.tailscale-interface"
fi
case "$sentinel_tailnet_interface" in
    ''|lo|*[!A-Za-z0-9_.-]*) echo 'ERROR: invalid Tailnet interface metadata' >&2; exit 1 ;;
esac
[ "${#sentinel_tailnet_interface}" -le 15 ] || { echo 'ERROR: invalid Tailnet interface length' >&2; exit 1; }

# A delay >=10s also makes the Docker restart policy effective when NGINX
# subsequently fails its bind. Missing addresses cannot cause a one-shot boot loss.
sentinel_elapsed=0
while [ "$sentinel_elapsed" -lt 60 ]; do
    sentinel_ready=yes
    sentinel_addresses=$(ip -o address show)
    while IFS= read -r sentinel_address; do
        if ! printf '%s\n' "$sentinel_addresses" | awk -v expected="$sentinel_address" -v tailnet="$sentinel_tailnet_interface" '
            ($3 == "inet" || $3 == "inet6") {
                split($4, ip, "/")
                interface=$2
                sub(/@.*/, "", interface)
                is_tailnet=(interface == tailnet)
                if (ip[1] == expected && is_tailnet) overlap=1
                if (ip[1] == expected && !is_tailnet && $0 !~ /tentative|dadfailed/) found=1
            }
            END { exit (!found || overlap) }
        '; then sentinel_ready=no; fi
    done < "$sentinel_current/.public-listen-addresses"
    if [ "$sentinel_ready" = yes ] && [ "$sentinel_elapsed" -ge 10 ]; then exec /docker-entrypoint.sh "$@"; fi
    sleep 1
    sentinel_elapsed=$((sentinel_elapsed + 1))
done
echo 'ERROR: explicit ingress address unavailable after 60s; Docker may retry, never falling back to wildcard' >&2
exit 75
