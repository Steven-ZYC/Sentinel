#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Steven Zhang
"""Create a sites.json manifest from the pre-manifest Sentinel .env format."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
RENDERER_PATH = Path(__file__).with_name("render-sites.py")
RENDERER_SPEC = importlib.util.spec_from_file_location("sentinel_render_sites", RENDERER_PATH)
if RENDERER_SPEC is None or RENDERER_SPEC.loader is None:
    raise RuntimeError(f"unable to load renderer module: {RENDERER_PATH}")
RENDERER_MODULE = importlib.util.module_from_spec(RENDERER_SPEC)
sys.modules[RENDERER_SPEC.name] = RENDERER_MODULE
RENDERER_SPEC.loader.exec_module(RENDERER_MODULE)
ConfigError = RENDERER_MODULE.ConfigError
parse_env = RENDERER_MODULE.parse_env


def value(env: dict[str, str], key: str, default: str | None = None) -> str:
    result = env.get(key, default)
    if not result:
        raise ConfigError(f"legacy .env is missing {key}")
    return result


def redirect_name(domain: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:8]
    return f"redirect-{base[:43].rstrip('-')}-{digest}"


def parse_redirect(value: str, certificate: str, private_key: str) -> dict[str, object]:
    if "=" not in value:
        raise ConfigError("--redirect must use domain=https://target.example syntax")
    domain, target = value.split("=", 1)
    if not domain or not target:
        raise ConfigError("--redirect must include both domain and HTTPS target")
    return {
        "name": redirect_name(domain),
        "type": "redirect",
        "domain": domain,
        "certificate": certificate,
        "private_key": private_key,
        "redirect_to": target,
    }


def legacy_site(
    *,
    name: str,
    domain: str,
    address: str,
    port: str,
    certificate: str,
    private_key: str,
    csp: str,
    permissions: str,
    client_max_body_size: str | None = None,
) -> dict[str, object]:
    try:
        upstream_port = int(port)
    except ValueError as error:
        raise ConfigError(f"legacy {name} upstream port is not an integer: {port}") from error
    site: dict[str, object] = {
        "name": name,
        "type": "proxy",
        "domain": domain,
        "certificate": certificate,
        "private_key": private_key,
        "upstream": {"address": address, "port": upstream_port, "scheme": "http"},
        "security": {
            "content_security_policy": csp,
            "permissions_policy": permissions,
        },
    }
    if client_max_body_size:
        site["client_max_body_size"] = client_max_body_size
    return site


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=PROJECT_DIR / ".env")
    parser.add_argument("--output", type=Path, default=PROJECT_DIR / "sites.json")
    parser.add_argument("--write", action="store_true", help="write the generated manifest")
    parser.add_argument("--force", action="store_true", help="replace an existing output file (requires --write)")
    parser.add_argument(
        "--redirect",
        action="append",
        default=[],
        metavar="DOMAIN=HTTPS_ORIGIN",
        help="include a legacy permanent redirect; may be specified more than once",
    )
    args = parser.parse_args()
    if args.force and not args.write:
        parser.error("--force requires --write")

    try:
        env = parse_env(args.env)
        certificate = value(env, "TLS_CERT_PATH")
        private_key = value(env, "TLS_KEY_PATH")
        csp = value(env, "CONTENT_SECURITY_POLICY")
        permissions = value(env, "PERMISSIONS_POLICY")
        if env.get("UPSTREAM_SCHEME", "http") != "http":
            raise ConfigError("legacy UPSTREAM_SCHEME must be http before migration")
        sites: list[dict[str, object]] = [
            legacy_site(
                name="app",
                domain=value(env, "DOMAIN"),
                address=value(env, "UPSTREAM_ADDR", "127.0.0.1"),
                port=value(env, "UPSTREAM_PORT", "10443"),
                certificate=certificate,
                private_key=private_key,
                csp=csp,
                permissions=permissions,
            )
        ]
        if env.get("GBA_DOMAIN"):
            sites.append(
                legacy_site(
                    name="gba",
                    domain=value(env, "GBA_DOMAIN"),
                    address=value(env, "GBA_UPSTREAM_ADDR", "127.0.0.1"),
                    port=value(env, "GBA_UPSTREAM_PORT", "10445"),
                    certificate=certificate,
                    private_key=private_key,
                    csp=csp,
                    permissions=permissions,
                    client_max_body_size="30m",
                )
            )
        sites.extend(parse_redirect(item, certificate, private_key) for item in args.redirect)
        manifest = {"version": 1, "sites": sites}
        payload = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
        if not args.write:
            sys.stdout.write(payload)
            print("Run again with --write after reviewing the manifest.", file=sys.stderr)
            return 0
        if args.output.exists() and not args.force:
            raise ConfigError(f"refusing to overwrite existing manifest: {args.output}; use --force after review")
        args.output.write_text(payload, encoding="utf-8")
        print(f"Wrote {args.output}")
        print("The renderer accepts existing TLS_CERT_PATH/TLS_KEY_PATH as a migration bridge.")
        print("Set TLS_MOUNT_ROOT to the parent certificate directory, then replace the legacy keys with DEFAULT_TLS_* before cleanup.")
    except ConfigError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
