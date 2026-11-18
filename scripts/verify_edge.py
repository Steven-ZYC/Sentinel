#!/usr/bin/env python3
"""Validate real public HTTPS responses, not merely header presence."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlsplit


def header_blocks(content: str) -> list[tuple[int, dict[str, list[str]]]]:
    blocks = []
    for block in re.split(r"\r?\n\r?\n", content):
        lines = block.splitlines()
        if not lines or not lines[0].startswith("HTTP/") or "Connection established" in lines[0]:
            continue
        status = int(lines[0].split()[1])
        if status < 200:
            continue
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers.setdefault(key.lower().strip(), []).append(value.strip())
        blocks.append((status, headers))
    return blocks


def validate_headers(blocks: list[tuple[int, dict[str, list[str]]]]) -> None:
    if not blocks or not 200 <= blocks[-1][0] < 300:
        raise ValueError("final HTTPS response must be successful, not an error or redirect")
    for _, headers in blocks:
        values = headers.get("strict-transport-security", [])
        if len(values) != 1:
            raise ValueError("each HTTPS hop must have exactly one HSTS header")
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*([0-9]+)\s*(?:;|$)", values[0], re.I)
        if not match or int(match[1]) < 31536000:
            raise ValueError("HSTS max-age must be at least 31536000; max-age=0 disables protection")
    headers = blocks[-1][1]
    expected = {
        "x-content-type-options": {"nosniff"},
        "x-frame-options": {"deny"},
        "referrer-policy": {"strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin"},
        "cross-origin-opener-policy": {"same-origin"},
        "cross-origin-resource-policy": {"same-origin"},
    }
    for name, values in expected.items():
        actual = headers.get(name, [])
        if len(actual) != 1 or actual[0].lower() not in values:
            raise ValueError(f"missing, duplicated or unsafe {name}")
    csp = headers.get("content-security-policy", [])
    if len(csp) != 1 or not re.search(r"(?:^|;)\s*default-src\s+[^;]+", csp[0]):
        raise ValueError("final response requires an enforced CSP with default-src")
    permissions = headers.get("permissions-policy", [])
    if len(permissions) != 1 or not permissions[0].strip():
        raise ValueError("final response requires a non-empty Permissions-Policy")
    for cookie in headers.get("set-cookie", []):
        attributes = [item.strip().lower() for item in cookie.split(";")[1:]]
        if "secure" not in attributes or "httponly" not in attributes or not any(item in ("samesite=lax", "samesite=strict") for item in attributes):
            raise ValueError("response cookie lacks Secure/HttpOnly/SameSite protection")


def tls_probe(host: str, port: int, protocol: str, ca_file: str | None = None) -> subprocess.CompletedProcess:
    endpoint = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    command = ["openssl", "s_client", "-connect", endpoint, "-servername", host, "-verify_hostname", host, "-verify_return_error", "-brief", protocol]
    if ca_file:
        command.extend(("-CAfile", ca_file))
    if protocol in ("-tls1", "-tls1_1"):
        command.extend(("-cipher", "ALL:@SECLEVEL=0"))
    return subprocess.run(command, input="", text=True, capture_output=True, timeout=15)


def assert_tls_result(result: subprocess.CompletedProcess, *, legacy: bool) -> None:
    output = result.stdout + result.stderr
    if not legacy:
        if result.returncode != 0 or "Protocol version: TLSv1.2" not in output or "Verification: OK" not in output:
            raise ValueError("verified TLS 1.2 baseline failed; cannot infer legacy TLS rejection")
    else:
        if result.returncode == 0 or "CONNECTION ESTABLISHED" in output:
            raise ValueError("legacy TLS handshake succeeded")
        if not re.search(r"alert (?:protocol version|handshake failure)", output, re.I):
            raise ValueError("legacy TLS test inconclusive (network/client error is not proof of rejection)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--ca-file", help="optional private CA bundle; certificate verification remains enabled")
    args = parser.parse_args()
    target = urlsplit(args.url)
    if target.scheme != "https" or not target.hostname or target.username or target.password or target.fragment:
        raise ValueError("provide an HTTPS URL without credentials or fragment")
    common = ["curl", "--silent", "--show-error", "--connect-timeout", "5", "--max-time", "20", "--proto", "=https", "--proto-redir", "=https"]
    if args.ca_file:
        common.extend(("--cacert", args.ca_file))
    with tempfile.TemporaryDirectory(prefix="sentinel-verify-") as directory:
        dump = Path(directory) / "headers"
        result = subprocess.run([*common, "--location", "--max-redirs", "5", "--dump-header", str(dump), "--output", "/dev/null", "--write-out", "%{url_effective}", args.url], check=True, capture_output=True, text=True, timeout=25)
        blocks = header_blocks(dump.read_text())
        validate_headers(blocks)
        final = result.stdout
        origins = {(target.hostname, target.port or 443)}
        hop = args.url
        for status, headers in blocks:
            if 300 <= status < 400 and headers.get("location"):
                hop = urljoin(hop, headers["location"][0])
                parsed = urlsplit(hop)
                origins.add((parsed.hostname, parsed.port or 443))
        print("OK: all HTTPS hops have effective HSTS; final status, security-header values and cookies checked")
    for method in ("TRACE", "TRACK"):
        code = subprocess.check_output([*common, "-X", method, "--output", "/dev/null", "--write-out", "%{http_code}", final], text=True, timeout=25)
        if code not in ("400", "403", "405", "501"):
            raise ValueError(f"{method} returned unapproved status {code}")
    print("OK: TRACE/TRACK explicitly rejected")
    for host, port in sorted(origins):
        assert_tls_result(tls_probe(host, port, "-tls1_2", args.ca_file), legacy=False)
        for protocol in ("-tls1", "-tls1_1"):
            assert_tls_result(tls_probe(host, port, protocol, args.ca_file), legacy=True)
    print("PASS: verified TLS 1.2 succeeds; TLS 1.0/1.1 explicitly rejected")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
