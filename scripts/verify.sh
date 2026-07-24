#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-${TARGET_URL:-}}
if [[ -z $TARGET ]]; then
    printf 'usage: %s https://app.example.com\n' "$0" >&2
    exit 2
fi
host=${TARGET#*://}
host=${host%%/*}
host=${host%%:*}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

curl --silent --show-error --location --max-time 15 --dump-header "$tmp" --output /dev/null "$TARGET"

required=(
  strict-transport-security
  content-security-policy
  x-content-type-options
  x-frame-options
  referrer-policy
  permissions-policy
  cross-origin-opener-policy
  cross-origin-resource-policy
)

for header in "${required[@]}"; do
    grep -qiE "^${header}:" "$tmp" || { printf 'FAIL missing header: %s\n' "$header" >&2; exit 1; }
done
printf 'OK: required security headers are present\n'

if curl --silent --show-error --max-time 10 -X TRACE -o /dev/null -w '%{http_code}' "$TARGET" | grep -qE '^(200|201|202|204)$'; then
    printf 'FAIL: TRACE returned a success status\n' >&2
    exit 1
fi
printf 'OK: TRACE is not accepted\n'

if openssl s_client -connect "$host:443" -servername "$host" -tls1 -cipher 'ALL:@SECLEVEL=0' </dev/null 2>&1 | grep -q 'Protocol  : TLSv1'; then
    printf 'FAIL: TLS 1.0 handshake succeeded\n' >&2
    exit 1
fi
printf 'OK: TLS 1.0 is rejected\n'

if openssl s_client -connect "$host:443" -servername "$host" -tls1_1 -cipher 'ALL:@SECLEVEL=0' </dev/null 2>&1 | grep -q 'Protocol  : TLSv1.1'; then
    printf 'FAIL: TLS 1.1 handshake succeeded\n' >&2
    exit 1
fi
printf 'OK: TLS 1.1 is rejected\n'

printf 'PASS: baseline edge checks completed for %s\n' "$TARGET"
