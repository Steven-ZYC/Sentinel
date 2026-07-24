#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Steven Zhang
"""Render the Sentinel site manifest into deterministic NGINX virtual hosts.

The manifest intentionally uses JSON instead of a shell-sourced format: site
data must be declarative, and rendering it must never execute user input.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SITES_FILE = PROJECT_DIR / "sites.json"
DEFAULT_ENV_FILE = PROJECT_DIR / ".env"
DEFAULT_OUTPUT_DIR = PROJECT_DIR / "nginx" / "generated"
CONTAINER_TLS_ROOT = "/etc/sentinel/tls"

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
SIZE_RE = re.compile(r"^(?:0|[1-9][0-9]*[kKmMgG]?)$")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ConfigError(ValueError):
    """A site manifest or global environment value is unsafe or invalid."""


@dataclass(frozen=True)
class Tls:
    certificate: str
    private_key: str


@dataclass(frozen=True)
class ProxySite:
    name: str
    domain: str
    tls: Tls
    upstream_port: int
    content_security_policy: str
    permissions_policy: str
    client_max_body_size: str | None


@dataclass(frozen=True)
class RedirectSite:
    name: str
    domain: str
    tls: Tls
    redirect_to: str


Site = ProxySite | RedirectSite


def fail(message: str) -> None:
    raise ConfigError(message)


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{field} must be a non-empty string")
    return value.strip()


def reject_control_characters(value: str, field: str, *, reject_dollar: bool = False) -> str:
    if any(character in value for character in ("\r", "\n", "\x00")):
        fail(f"{field} must not contain a newline or NUL byte")
    if reject_dollar and "$" in value:
        fail(f"{field} must not contain '$' because NGINX would expand it")
    return value


def nginx_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def normalize_domain(value: Any, field: str) -> str:
    domain = require_string(value, field).rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as error:
        fail(f"{field} is not a valid IDNA hostname: {error}")
    if len(domain) > 253 or "." not in domain:
        fail(f"{field} must be a fully qualified hostname")
    labels = domain.split(".")
    if any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        fail(f"{field} contains an invalid hostname label")
    return domain


def absolute_path(value: Any, field: str) -> str:
    path = require_string(value, field)
    reject_control_characters(path, field)
    if not Path(path).is_absolute():
        fail(f"{field} must be an absolute path")
    return path


def parse_tls(data: dict[str, Any], field_prefix: str) -> Tls:
    return Tls(
        certificate=absolute_path(data.get("certificate"), f"{field_prefix}.certificate"),
        private_key=absolute_path(data.get("private_key"), f"{field_prefix}.private_key"),
    )


def parse_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"environment file is missing: {path}")
    result: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in line:
            fail(f"{path}:{number} must use KEY=value syntax")
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            fail(f"{path}:{number} has an invalid environment key")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[key] = value
    return result


def parse_public_address(env: dict[str, str]) -> str:
    address = require_string(env.get("PUBLIC_LISTEN_ADDR"), "PUBLIC_LISTEN_ADDR")
    try:
        parsed = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError as error:
        fail(f"PUBLIC_LISTEN_ADDR must be one explicit IPv4 address: {error}")
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        fail("PUBLIC_LISTEN_ADDR must not be wildcard, loopback, or multicast")
    return str(parsed)


def parse_default_tls(env: dict[str, str]) -> Tls:
    # TLS_CERT_PATH/TLS_KEY_PATH are supported only as a migration bridge for
    # existing installations. New deployments should use DEFAULT_TLS_*.
    certificate = env.get("DEFAULT_TLS_CERT_PATH") or env.get("TLS_CERT_PATH")
    private_key = env.get("DEFAULT_TLS_KEY_PATH") or env.get("TLS_KEY_PATH")
    return Tls(
        certificate=absolute_path(certificate, "DEFAULT_TLS_CERT_PATH"),
        private_key=absolute_path(private_key, "DEFAULT_TLS_KEY_PATH"),
    )


def parse_tls_mount_root(env: dict[str, str]) -> str:
    return absolute_path(env.get("TLS_MOUNT_ROOT"), "TLS_MOUNT_ROOT")


def container_tls(tls: Tls, mount_root: str) -> Tls:
    """Map a host certificate path under TLS_MOUNT_ROOT into the container."""
    root = Path(mount_root).resolve()

    def map_path(value: str, field: str) -> str:
        try:
            relative = Path(value).resolve().relative_to(root)
        except ValueError:
            fail(f"{field} must be inside TLS_MOUNT_ROOT ({root}): {value}")
        if str(relative) == ".":
            fail(f"{field} must name a file below TLS_MOUNT_ROOT")
        return f"{CONTAINER_TLS_ROOT}/{relative.as_posix()}"

    return Tls(
        certificate=map_path(tls.certificate, "certificate"),
        private_key=map_path(tls.private_key, "private_key"),
    )


def expect_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{field} must be an object")
    return value


def reject_unknown_keys(data: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        fail(f"{field} contains unsupported key(s): {', '.join(unknown)}")


def parse_redirect_target(value: Any, field: str) -> str:
    target = reject_control_characters(require_string(value, field), field, reject_dollar=True)
    parsed = urlsplit(target)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        fail(f"{field} must be an HTTPS origin without a path, query, or fragment")
    hostname = normalize_domain(parsed.hostname, field)
    try:
        port_value = parsed.port
    except ValueError as error:
        fail(f"{field} has an invalid HTTPS port: {error}")
    port = f":{port_value}" if port_value is not None else ""
    return urlunsplit(("https", f"{hostname}{port}", "", "", ""))


def parse_site(data: Any, index: int) -> Site:
    field = f"sites[{index}]"
    item = expect_object(data, field)
    site_type = item.get("type", "proxy")
    if site_type not in ("proxy", "redirect"):
        fail(f"{field}.type must be proxy or redirect")
    common = {"name", "type", "domain", "certificate", "private_key"}
    if site_type == "proxy":
        reject_unknown_keys(
            item,
            common | {"upstream", "security", "client_max_body_size"},
            field,
        )
    else:
        reject_unknown_keys(item, common | {"redirect_to"}, field)

    name = require_string(item.get("name"), f"{field}.name")
    if not NAME_RE.fullmatch(name):
        fail(f"{field}.name must match {NAME_RE.pattern}")
    domain = normalize_domain(item.get("domain"), f"{field}.domain")
    tls = parse_tls(item, field)

    if site_type == "redirect":
        return RedirectSite(
            name=name,
            domain=domain,
            tls=tls,
            redirect_to=parse_redirect_target(item.get("redirect_to"), f"{field}.redirect_to"),
        )

    upstream = expect_object(item.get("upstream"), f"{field}.upstream")
    reject_unknown_keys(upstream, {"address", "port", "scheme"}, f"{field}.upstream")
    address = require_string(upstream.get("address"), f"{field}.upstream.address")
    if address != "127.0.0.1":
        fail(f"{field}.upstream.address must be 127.0.0.1")
    port = upstream.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        fail(f"{field}.upstream.port must be an integer between 1 and 65535")
    if port in (80, 443, 9443):
        fail(f"{field}.upstream.port must not use Sentinel or SafeLine management port {port}")
    if upstream.get("scheme") != "http":
        fail(f"{field}.upstream.scheme must be http for a SafeLine internal listener")

    security = expect_object(item.get("security"), f"{field}.security")
    reject_unknown_keys(
        security,
        {"content_security_policy", "permissions_policy"},
        f"{field}.security",
    )
    csp = reject_control_characters(
        require_string(security.get("content_security_policy"), f"{field}.security.content_security_policy"),
        f"{field}.security.content_security_policy",
        reject_dollar=True,
    )
    permissions = reject_control_characters(
        require_string(security.get("permissions_policy"), f"{field}.security.permissions_policy"),
        f"{field}.security.permissions_policy",
        reject_dollar=True,
    )
    body_size = item.get("client_max_body_size")
    if body_size is not None:
        body_size = require_string(body_size, f"{field}.client_max_body_size")
        if not SIZE_RE.fullmatch(body_size):
            fail(f"{field}.client_max_body_size is not an NGINX size")

    return ProxySite(
        name=name,
        domain=domain,
        tls=tls,
        upstream_port=port,
        content_security_policy=csp,
        permissions_policy=permissions,
        client_max_body_size=body_size,
    )


def load_sites(path: Path) -> list[Site]:
    if not path.is_file():
        fail(f"site manifest is missing: {path}; copy sites.example.json to sites.json")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"site manifest is not valid JSON: {error}")
    manifest = expect_object(manifest, "manifest")
    reject_unknown_keys(manifest, {"version", "sites"}, "manifest")
    if manifest.get("version") != 1:
        fail("manifest.version must be 1")
    raw_sites = manifest.get("sites")
    if not isinstance(raw_sites, list) or not raw_sites:
        fail("manifest.sites must be a non-empty array")
    sites = [parse_site(item, index) for index, item in enumerate(raw_sites)]
    names = [site.name for site in sites]
    domains = [site.domain for site in sites]
    duplicate_names = sorted({name for name in names if names.count(name) > 1})
    duplicate_domains = sorted({domain for domain in domains if domains.count(domain) > 1})
    if duplicate_names:
        fail(f"manifest has duplicate site name(s): {', '.join(duplicate_names)}")
    if duplicate_domains:
        fail(f"manifest has duplicate domain(s): {', '.join(duplicate_domains)}")
    proxy_ports = [site.upstream_port for site in sites if isinstance(site, ProxySite)]
    duplicates = sorted({port for port in proxy_ports if proxy_ports.count(port) > 1})
    if duplicates:
        fail("each proxy site needs a distinct SafeLine listener port; duplicate: " + ", ".join(map(str, duplicates)))
    if not any(isinstance(site, ProxySite) for site in sites):
        fail("manifest must contain at least one proxy site for the health check")
    return sites


def tls_lines(tls: Tls) -> str:
    return "\n".join(
        (
            f'    ssl_certificate "{nginx_quote(tls.certificate)}";',
            f'    ssl_certificate_key "{nginx_quote(tls.private_key)}";',
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;",
            "    ssl_prefer_server_ciphers off;",
        )
    )


def security_headers(site: ProxySite) -> str:
    return "\n".join(
        (
            '    add_header Strict-Transport-Security "max-age=31536000" always;',
            f'    add_header Content-Security-Policy "{nginx_quote(site.content_security_policy)}" always;',
            '    add_header X-Content-Type-Options "nosniff" always;',
            '    add_header X-Frame-Options "DENY" always;',
            '    add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            f'    add_header Permissions-Policy "{nginx_quote(site.permissions_policy)}" always;',
            '    add_header Cross-Origin-Opener-Policy "same-origin" always;',
            '    add_header Cross-Origin-Resource-Policy "same-origin" always;',
            '    add_header X-Permitted-Cross-Domain-Policies "none" always;',
        )
    )


def render_default(address: str, tls: Tls) -> str:
    return f"""# Generated by scripts/render-sites.py. Do not edit.
server {{
    listen {address}:80 default_server;
    server_name _;
    return 421;
}}

server {{
    listen {address}:443 ssl default_server;
    http2 on;
    server_name _;
{tls_lines(tls)}
    return 421;
}}
"""


def render_proxy(address: str, site: ProxySite, tls: Tls) -> str:
    body_size = f"    client_max_body_size {site.client_max_body_size};\n" if site.client_max_body_size else ""
    return f"""# Generated by scripts/render-sites.py. Do not edit.
upstream sentinel_{site.name.replace('-', '_')} {{
    server 127.0.0.1:{site.upstream_port};
    keepalive 32;
}}

server {{
    listen {address}:80;
    server_name {site.domain};

    location = /.sentinel/health {{
        access_log off;
        default_type text/plain;
        return 200 "ok\\n";
    }}

    location / {{
        return 308 https://$host$request_uri;
    }}
}}

server {{
    listen {address}:443 ssl;
    http2 on;
    server_name {site.domain};
{tls_lines(tls)}
{body_size}{security_headers(site)}

    location = /.sentinel/health {{
        access_log off;
        default_type text/plain;
        return 200 "ok\\n";
    }}

    if ($request_method ~* "^(TRACE|TRACK|CONNECT)$") {{ return 405; }}

    location / {{
        proxy_pass http://sentinel_{site.name.replace('-', '_')};
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header CF-Connecting-IP "";
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_cookie_flags ~ secure httponly samesite=lax;

        proxy_hide_header Server;
        proxy_hide_header X-Powered-By;
        proxy_hide_header Content-Security-Policy;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Permissions-Policy;
    }}
}}
"""


def render_redirect(address: str, site: RedirectSite, tls: Tls) -> str:
    target = nginx_quote(site.redirect_to)
    return f"""# Generated by scripts/render-sites.py. Do not edit.
server {{
    listen {address}:80;
    server_name {site.domain};

    location / {{
        return 308 {target}$request_uri;
    }}
}}

server {{
    listen {address}:443 ssl;
    http2 on;
    server_name {site.domain};
{tls_lines(tls)}
    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {{
        return 308 {target}$request_uri;
    }}
}}
"""


def rendered_files(address: str, mount_root: str, default_tls: Tls, sites: list[Site]) -> dict[str, str]:
    files = {"00-default.conf": render_default(address, container_tls(default_tls, mount_root))}
    for index, site in enumerate(sites, start=10):
        filename = f"{index:02d}-{site.name}.conf"
        tls = container_tls(site.tls, mount_root)
        files[filename] = render_proxy(address, site, tls) if isinstance(site, ProxySite) else render_redirect(address, site, tls)
    health_site = next(site for site in sites if isinstance(site, ProxySite))
    files[".healthcheck-host"] = f"{health_site.domain}\n"
    return files


def validate_certificates(mount_root: str, default_tls: Tls, sites: list[Site]) -> None:
    root = Path(mount_root)
    if not root.is_dir() or not os.access(root, os.R_OK | os.X_OK):
        fail(f"TLS_MOUNT_ROOT is not a readable directory: {root}")
    checked: set[tuple[str, str]] = set()
    for label, tls in [("default TLS", default_tls)] + [(site.domain, site.tls) for site in sites]:
        pair = (tls.certificate, tls.private_key)
        if pair in checked:
            continue
        checked.add(pair)
        for kind, value in (("certificate", tls.certificate), ("private key", tls.private_key)):
            path = Path(value)
            if not path.is_file() or not os.access(path, os.R_OK):
                fail(f"{label} {kind} is not a readable regular file: {path}")


def write_rendered_files(output: Path, files: dict[str, str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    expected = set(files)
    for path in output.iterdir():
        if path.name == ".gitkeep":
            continue
        if path.name in expected or path.suffix == ".conf" or path.name == ".healthcheck-host":
            path.unlink()
    for name, content in files.items():
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output, delete=False) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output / name)


def check_rendered_files(output: Path, files: dict[str, str]) -> None:
    stale = [name for name, content in files.items() if not (output / name).is_file() or (output / name).read_text(encoding="utf-8") != content]
    unexpected = [
        path.name
        for path in output.glob("*.conf")
        if path.name not in files
    ] if output.is_dir() else []
    if stale or unexpected:
        details = []
        if stale:
            details.append("missing or stale: " + ", ".join(stale))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        fail("generated NGINX configuration is out of date (" + "; ".join(details) + "); run ./scripts/render-sites.py")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sites", type=Path, default=DEFAULT_SITES_FILE, help="site manifest path")
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV_FILE, help="global environment file path")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_DIR, help="generated configuration directory")
    parser.add_argument("--check", action="store_true", help="validate that generated files are current without writing")
    parser.add_argument("--check-certificates", action="store_true", help="require every certificate and key path to be readable")
    parser.add_argument("--list-upstreams", action="store_true", help="print proxy domain, address, and port as tab-separated rows")
    parser.add_argument("--list-certificates", action="store_true", help="print certificate/key paths as tab-separated rows")
    arguments = parser.parse_args()
    if sum((arguments.check, arguments.list_upstreams, arguments.list_certificates)) > 1:
        parser.error("--check, --list-upstreams, and --list-certificates are mutually exclusive")

    try:
        env = parse_env(arguments.env)
        address = parse_public_address(env)
        tls_mount_root = parse_tls_mount_root(env)
        default_tls = parse_default_tls(env)
        sites = load_sites(arguments.sites)
        if arguments.check_certificates:
            validate_certificates(tls_mount_root, default_tls, sites)

        if arguments.list_upstreams:
            for site in sites:
                if isinstance(site, ProxySite):
                    print(f"{site.domain}\t127.0.0.1\t{site.upstream_port}")
            return 0
        if arguments.list_certificates:
            printed: set[tuple[str, str]] = set()
            for tls in [default_tls] + [site.tls for site in sites]:
                pair = (tls.certificate, tls.private_key)
                if pair not in printed:
                    printed.add(pair)
                    print(f"{tls.certificate}\t{tls.private_key}")
            return 0

        files = rendered_files(address, tls_mount_root, default_tls, sites)
        if arguments.check:
            check_rendered_files(arguments.output, files)
        else:
            write_rendered_files(arguments.output, files)
    except ConfigError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
