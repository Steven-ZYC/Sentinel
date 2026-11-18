#!/usr/bin/env python3
"""Shared fail-closed runtime checks. No dependency on a DNS provider."""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import listener_boundary as boundary


def renderer():
    name = "sentinel_renderer"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("render-sites.py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def run(*args: str, timeout: int = 30) -> str:
    return subprocess.check_output(args, text=True, timeout=timeout)


def addresses(port: int) -> set[str]:
    rows = run("ss", "-H", "-ltn", f"sport = :{port}")
    return {re.sub(r"%[\w.\-]+", "", row.split()[3]) for row in rows.splitlines() if row.strip()}


def assert_loopback(port: int, listeners: set[str]) -> None:
    allowed = {f"127.0.0.1:{port}", f"[::1]:{port}", f"::1:{port}"}
    if f"127.0.0.1:{port}" not in listeners or not listeners <= allowed:
        raise ValueError(f"port {port} must listen on 127.0.0.1 only (optional ::1); found {sorted(listeners)}")


def safeline_container(project: Path) -> str:
    env_file = project / ".env"
    env = renderer().parse_env(env_file) if env_file.is_file() else {}
    return os.environ.get("SAFELINE_CONTAINER") or env.get("SAFELINE_CONTAINER", "safeline-tengine")


def check_upstreams(project: Path) -> None:
    module = renderer()
    ports = {site.upstream_port for site in module.load_sites(project / "sites.json")
             if isinstance(site, module.ProxySite)}
    container = safeline_container(project)
    identity = run("docker", "inspect", "--type", "container", "--format", "{{.Id}}", "--", container).strip()
    if not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise ValueError("cannot establish SafeLine container identity")
    rows = boundary.listeners(ports)
    for port in ports:
        matches = [row for row in rows if row.address.endswith(f":{port}")]
        assert_loopback(port, {row.address for row in matches})
        for row in matches:
            boundary.require_owner(row, lambda pid: boundary.owned_by_proxy(pid, {"Id": identity}))


def assert_serve(state: dict, port: int = 443, management_port: int = 9443, *, allow_empty: bool = False) -> None:
    if not isinstance(state, dict):
        raise ValueError("Serve state must be an object")
    if set(state) - {"TCP", "Web", "AllowFunnel", "Foreground"}:
        raise ValueError("unknown/Services Serve state is not approved")
    def reject_funnel(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "AllowFunnel" and item:
                    raise ValueError("AllowFunnel must be empty: public Funnel is forbidden")
                if key == "Foreground" and item:
                    raise ValueError("foreground Serve configurations are not approved")
                reject_funnel(item)
        elif isinstance(value, list):
            for item in value:
                reject_funnel(item)
    reject_funnel(state)
    tcp = state.get("TCP", {})
    web = state.get("Web", {})
    if not isinstance(tcp, dict) or not isinstance(web, dict):
        raise ValueError("Serve TCP/Web must be objects")
    if allow_empty and not tcp and not web:
        return
    if tcp.get(str(port)) != {"HTTPS": True}:
        raise ValueError("Serve HTTPS listener differs from the approved policy")
    approved_tcp = {str(port)}
    if str(management_port) in tcp:
        if tcp[str(management_port)] != {"TCPForward": f"127.0.0.1:{management_port}"}:
            raise ValueError("unapproved management TCP forward")
        approved_tcp.add(str(management_port))
    if set(tcp) != approved_tcp or not web:
        raise ValueError("additional Serve listeners or missing Web routes")
    for address, listener in web.items():
        if not address.endswith(f".ts.net:{port}"):
            raise ValueError(f"unapproved Serve hostname: {address}")
        if listener != {"Handlers": {"/": {"Proxy": f"https+insecure://localhost:{management_port}"}}}:
            raise ValueError("additional Serve routes or changed management target")


def check_management(tailscale: str | None = None) -> None:
    actual = addresses(9443)
    if tailscale is None:
        assert_loopback(9443, actual)
        return
    state = json.loads(run(tailscale, "serve", "status", "--json"))
    assert_serve(state)
    status = json.loads(run(tailscale, "status", "--json"))
    if status.get("BackendState") != "Running":
        raise ValueError("Tailscale is not running")
    allowed = {"127.0.0.1:9443", "[::1]:9443", "::1:9443"}
    if "9443" in state.get("TCP", {}):
        for value in status.get("Self", {}).get("TailscaleIPs", []):
            ip = ipaddress.ip_address(value)
            allowed.add(f"[{ip}]:9443" if ip.version == 6 else f"{ip}:9443")
    if "127.0.0.1:9443" not in actual or not actual <= allowed:
        raise ValueError(f"unapproved management bindings: {sorted(actual)}")


def check_tailnet_boundary(project: Path, tailscale: str = "tailscale") -> None:
    # Requires actual listeners and daemon ownership, not just persisted JSON.
    from runtime_guard import check_tailnet, check_public
    check_tailnet(project, tailscale)
    check_public(project)


def check_certificates(project: Path) -> None:
    module = renderer()
    env = module.parse_env(project / ".env")
    sites = module.load_sites(project / "sites.json")
    default = module.parse_default_tls(env)
    mount = Path(module.parse_tls_mount_root(env))
    if len(mount.resolve().parts) < 3:
        raise ValueError("TLS_MOUNT_ROOT must be a dedicated certificate directory")
    module.validate_certificates(str(mount), default, sites)
    checked = set()
    for tls in [default] + [site.tls for site in sites]:
        if (tls.certificate, tls.private_key) in checked:
            continue
        checked.add((tls.certificate, tls.private_key))
        for filename in (tls.certificate, tls.private_key):
            path = Path(filename)
            for component in (path, *path.parents, path.resolve(), *path.resolve().parents):
                metadata = component.stat()
                if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ValueError(f"TLS files and ancestor directories must be root-owned and protected: {component}")
        run("openssl", "x509", "-in", tls.certificate, "-noout", "-checkend", "604800")
        cert_key = run("openssl", "x509", "-in", tls.certificate, "-pubkey", "-noout")
        private_key = run("openssl", "pkey", "-in", tls.private_key, "-pubout")
        if cert_key != private_key:
            raise ValueError("certificate/private key mismatch (key material not logged)")
    for site in sites:
        # openssl -checkhost may return success even when the hostname does not match.
        result = run("openssl", "x509", "-in", site.tls.certificate, "-noout", "-checkhost", site.domain)
        if "does match certificate" not in result:
            raise ValueError(f"certificate does not cover {site.domain}")


if __name__ == "__main__":
    try:
        action = sys.argv[1]
        project = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else Path(__file__).resolve().parents[1]
        if action == "upstreams":
            check_upstreams(project)
        elif action == "certificates":
            check_certificates(project)
        elif action == "tailnet":
            check_tailnet_boundary(project, sys.argv[3] if len(sys.argv) > 3 else "tailscale")
        elif action == "management":
            check_management()
        elif action == "management-tailnet":
            check_management("tailscale")
        elif action in ("serve", "serve-or-empty"):
            assert_serve(json.load(sys.stdin), allow_empty=action == "serve-or-empty")
        else:
            raise ValueError("unknown check")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
