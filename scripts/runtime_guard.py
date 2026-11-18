#!/usr/bin/env python3
"""Bounded reconciliation; Docker owns startup, Tailscale is entirely optional."""
from __future__ import annotations

import argparse
import fcntl
import http.client
import hmac
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import listener_boundary as boundary
from security_checks import assert_serve, check_upstreams, renderer


def configuration(project: Path):
    module = renderer()
    env = module.parse_env(project / ".env")
    sites = module.load_sites(project / "sites.json")
    public = module.public_addresses(env)
    files = module.rendered_files(public[0], module.parse_tls_mount_root(env), module.parse_default_tls(env), sites, env)
    port = module.healthcheck_port(env, sites)
    bootstrap = (project / "nginx/nginx.conf").read_text()
    if bootstrap != (module.PROJECT_DIR / "nginx/nginx.conf").read_text():
        raise boundary.UnsafeState("bootstrap differs from the reviewed guard snapshot; explicit root deployment/reinstallation required")
    boundary.validate_configuration(bootstrap, files, public, port)
    return module, env, sites, public, files, port


def checked_revision(project: Path):
    module, env, sites, public, files, port = configuration(project)
    current = project / "nginx/generated/current"
    if not current.is_symlink() or current.resolve().parent != (project / "nginx/generated/.revisions").resolve():
        raise boundary.UnsafeState("deploy an atomic current revision before enabling recovery")
    module.check_rendered_files(current.parent, files)
    for path in [current.resolve(), *current.iterdir()]:
        if path.stat().st_mode & 0o022 or (path.is_file() and not path.stat().st_mode & 0o004):
            raise boundary.UnsafeState(f"unsafe generated configuration permissions: {path.name}")
    return env, sites, public, files, port, current.resolve()


def preflight(project: Path, files: dict[str, str], env: dict[str, str], docker: str = "docker") -> None:
    module = renderer()
    sites = module.load_sites(project / "sites.json")
    public = module.public_addresses(env)
    port = module.healthcheck_port(env, sites)
    boundary.validate_configuration((project / "nginx/nginx.conf").read_text(), files, public, port)
    rows = boundary.interfaces()
    boundary.assigned_public(public, env, rows)
    try:
        proxy = boundary.inspect_proxy(project, docker)
    except boundary.MissingProxy:
        proxy = None
    boundary.public_sockets(public, port, proxy, rows, required=False, env=env)


def local_health(current: Path) -> None:
    port = int((current / ".healthcheck-port").read_text())
    digest = (current / ".config-digest").read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}/.sentinel/health", timeout=3) as response:
            if response.status == 200 and response.read(64) == b"ok\n" and response.headers.get("X-Sentinel-Config") == digest:
                return
    except OSError as error:
        raise boundary.NotReady(f"local revision health probe failed: {error}") from error
    raise boundary.NotReady("running NGINX configuration digest differs from the published revision")


def public_tls(public: list[str], sites: list, *, port: int = 443) -> None:
    site = next(site for site in sites if isinstance(site, renderer().ProxySite))
    # Trust the explicitly configured certificate, including private Origin CAs.
    # Partial-chain verification still checks signature, expiry and hostname.
    context = ssl.create_default_context(cafile=site.tls.certificate)
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    leaf = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", Path(site.tls.certificate).read_text(), re.DOTALL)
    if leaf is None:
        raise boundary.UnsafeState("declared public TLS certificate is missing")
    expected_der = ssl.PEM_cert_to_DER_cert(leaf[0])
    for ip in public:
        try:
            with socket.create_connection((ip.strip("[]"), port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=site.domain) as secured:
                    if not hmac.compare_digest(secured.getpeercert(binary_form=True), expected_der):
                        raise boundary.NotReady("NGINX served a different certificate than the declared one")
        except OSError as error:
            raise boundary.NotReady(f"public TLS probe failed for {ip}:443: {error}") from error


def check_public(project: Path, docker: str = "docker") -> None:
    env, sites, public, files, port, current = checked_revision(project)
    rows = boundary.interfaces()
    boundary.assigned_public(public, env, rows)
    proxy = boundary.inspect_proxy(project, docker, recovery=True)
    state = proxy.get("State", {})
    if not state.get("Running") or state.get("Restarting") or state.get("Paused"):
        if state.get("Restarting"):
            raise boundary.NotReady("Docker is restarting Sentinel; guard will not compete with it")
        raise boundary.UnsafeState("Sentinel is stopped; guard never starts a possibly manually stopped container")
    boundary.public_sockets(public, port, proxy, rows, required=True, env=env)
    dump = boundary.command(docker, "exec", proxy["Id"], "nginx", "-T")
    boundary.validate_dump(dump, public, port, {name for name in files if name.endswith(".conf")})
    check_upstreams(project)
    local_health(current)
    public_tls(public, sites)


def retry(check, *, timeout: float = 60, interval: float = 2) -> None:
    if not 0 < timeout <= 120 or not 0 < interval <= 10:
        raise boundary.UnsafeState("retry timeout/interval outside permitted bounds")
    deadline = time.monotonic() + timeout
    while True:
        try:
            check()
            return
        except (boundary.NotReady, OSError, subprocess.SubprocessError) as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise boundary.NotReady(f"bounded recovery timed out: {error}") from error
            time.sleep(min(interval, remaining))


@contextmanager
def publication_lock(project: Path):
    path = project / "nginx/generated/.publish.lock"
    with path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise boundary.NotReady("publication in progress; recovery skipped without changing services")
        yield


def root_only() -> None:
    if os.geteuid() != 0:
        raise boundary.UnsafeState("reconciliation requires root; read-only inspect is available without root")


def recovery_slot(directory: Path, cooldown: float = 300) -> None:
    # Shared between invocations: a broken app must not cause one restart per tick.
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise boundary.UnsafeState("recovery state directory must be root-owned, private and not a symlink")
    path = directory / "public-last-restart"
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "r+") as state:
        if os.fstat(state.fileno()).st_uid != 0:
            raise boundary.UnsafeState("untrusted recovery cooldown state")
        previous = state.read().strip()
        now = time.time()
        if previous and now - float(previous) < cooldown:
            raise boundary.NotReady("public recovery cooldown active; no repeated restart")
        state.seek(0)
        state.truncate()
        state.write(str(now))
        state.flush()
        os.fsync(state.fileno())


@contextmanager
def tailnet_lock(directory: Path):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise boundary.UnsafeState("Tailnet recovery lock directory is not private/root-owned")
    descriptor = os.open(directory / "tailnet-reconcile.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise boundary.NotReady("another Tailnet reconciliation is active; no concurrent Serve writes")
        yield


def reconcile_public(project: Path, docker: str = "docker", *, timeout: float = 60, state_dir: Path = Path("/run/sentinel")) -> None:
    root_only()
    with publication_lock(project):
        repaired = False
        def attempt():
            nonlocal repaired
            try:
                check_public(project, docker)
                return
            except boundary.NotReady:
                if repaired:
                    raise
            # Recheck all safety prerequisites immediately before the only mutation.
            env, sites, public, files, port, current = checked_revision(project)
            rows = boundary.interfaces()
            boundary.assigned_public(public, env, rows)
            proxy = boundary.inspect_proxy(project, docker, recovery=True)
            state = proxy.get("State", {})
            if state.get("Restarting"):
                raise boundary.NotReady("Docker is already recovering Sentinel")
            if not state.get("Running") or state.get("Paused"):
                raise boundary.UnsafeState("stopped/paused Sentinel will not be started by the guard")
            if state.get("Health", {}).get("Status") == "starting":
                raise boundary.NotReady("container is starting; leave recovery to Docker")
            boundary.public_sockets(public, port, proxy, rows, required=False, env=env)
            check_upstreams(project)
            renderer().validate_certificates(renderer().parse_tls_mount_root(env), renderer().parse_default_tls(env), sites)
            for certificate in {site.tls.certificate for site in sites} | {renderer().parse_default_tls(env).certificate}:
                boundary.command("openssl", "x509", "-in", certificate, "-noout", "-checkend", "0")
            dump = boundary.command(docker, "exec", proxy["Id"], "nginx", "-T")
            boundary.validate_dump(dump, public, port, {name for name in files if name.endswith(".conf")})
            # Reinspection prevents targeting a replacement container by its shared name.
            latest = boundary.inspect_proxy(project, docker, recovery=True)
            if latest["Id"] != proxy["Id"] or not latest.get("State", {}).get("Running") or latest.get("State", {}).get("Restarting") or latest.get("State", {}).get("Paused"):
                raise boundary.NotReady("container changed during checks; no restart")
            recovery_slot(state_dir)
            boundary.command(docker, "restart", "--time", "10", proxy["Id"], timeout=25)
            repaired = True
            print("RECOVER: restarted the verified running Sentinel container once; no Tailscale changes")
            raise boundary.NotReady("waiting for repaired Sentinel listeners and TLS")
        retry(attempt, timeout=timeout)
    print("PASS: public listeners, ownership, include graph, revision digest and TLS verified")


def tailnet_state(project: Path, tailscale: str):
    env = renderer().parse_env(project / ".env")
    tailnet_name = boundary.configured_tailnet_interface(env)
    state = json.loads(boundary.command(tailscale, "serve", "status", "--json"))
    assert_serve(state, allow_empty=True)
    status = json.loads(boundary.command(tailscale, "status", "--json"))
    if status.get("BackendState") != "Running":
        raise boundary.NotReady("Tailscale is not online")
    raw_ips = status.get("Self", {}).get("TailscaleIPs", [])
    rows = boundary.interfaces()
    assigned = boundary.interface_ips(rows, tailnet_only=True, tailnet_name=tailnet_name)
    ips = [str(ip) for ip in raw_ips if str(ip) in assigned]
    if not ips:
        raise boundary.NotReady(f"Tailnet addresses have not been assigned to {tailnet_name}")
    public = renderer().public_addresses(env)
    if {ip.strip("[]") for ip in public} & set(raw_ips):
        raise boundary.UnsafeState("public and Tailnet listeners overlap")
    hostname = status.get("Self", {}).get("DNSName", "").rstrip(".")
    if not hostname.endswith(".ts.net") or any(char in hostname for char in "/\n\r\t "):
        raise boundary.UnsafeState("missing/invalid local Tailscale DNS identity")
    pid = boundary.tailscale_pid()
    if pid <= 0:
        raise boundary.NotReady("verified tailscaled PID not available")
    return state, ips, hostname, pid


def tailnet_sockets(state: dict, ips: list[str], pid: int, *, required: bool) -> None:
    https = {boundary.endpoint(ip, 443) for ip in ips}
    native = {boundary.endpoint(ip, 9443) for ip in ips} if "9443" in state.get("TCP", {}) else set()
    actual = boundary.listeners({443, 9443})
    management = {"127.0.0.1:9443", "[::1]:9443"}
    seen = set()
    for listener in actual:
        address = listener.address
        if address in https | native:
            boundary.require_owner(listener, lambda owner: owner == pid)
            seen.add(address)
        elif address.endswith(":9443") and address not in management:
            raise boundary.UnsafeState(f"unapproved management listener: {listener.detail}")
        elif address in {"0.0.0.0:443", "*:443", "[::]:443"}:
            raise boundary.UnsafeState(f"wildcard 443 conflicts with Tailnet isolation: {listener.detail}")
        elif pid in listener.pids:
            raise boundary.UnsafeState(f"tailscaled listening outside its approved Tailnet addresses: {listener.detail}")
    if "127.0.0.1:9443" not in {listener.address for listener in actual}:
        raise boundary.NotReady("loopback SafeLine management listener is not ready")
    if required and (https | native) - seen:
        raise boundary.NotReady(f"missing actual Tailnet listeners: {sorted((https | native) - seen)}")


def tailnet_https(ips: list[str], hostname: str) -> None:
    # Connect directly to the assigned IP; validate the .ts.net TLS hostname.
    for ip in ips:
        connection = http.client.HTTPSConnection(hostname, 443, context=ssl.create_default_context(), timeout=3)
        connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection((ip, 443), timeout)
        try:
            connection.request("HEAD", "/")
            response = connection.getresponse()
            if not 200 <= response.status < 500:
                raise boundary.NotReady(f"Tailnet management returned HTTP {response.status}")
        except OSError as error:
            raise boundary.NotReady(f"verified Tailnet HTTPS probe failed: {error}") from error
        finally:
            connection.close()


def check_tailnet(project: Path, tailscale: str = "tailscale") -> None:
    state, ips, hostname, pid = tailnet_state(project, tailscale)
    assert_serve(state)
    if f"{hostname}:443" not in state.get("Web", {}):
        raise boundary.NotReady("Serve does not include this node's current DNS name")
    tailnet_sockets(state, ips, pid, required=True)
    tailnet_https(ips, hostname)


def ensure_tailnet(project: Path, tailscale: str = "tailscale", *, timeout: float = 60, state_dir: Path = Path("/run/sentinel")) -> None:
    root_only()
    changed = False
    def attempt():
        nonlocal changed
        state, ips, hostname, pid = tailnet_state(project, tailscale)
        tailnet_sockets(state, ips, pid, required=False)
        empty = not state.get("TCP") and not state.get("Web")
        if not changed and (empty or f"{hostname}:443" not in state.get("Web", {})):
            # Only an empty or already approved config may be changed. Never reset.
            latest = json.loads(boundary.command(tailscale, "serve", "status", "--json"))
            assert_serve(latest, allow_empty=True)
            if latest != state:
                raise boundary.UnsafeState("Serve state changed concurrently; no modification")
            boundary.command(tailscale, "serve", "--bg", "--yes", "--https=443", "https+insecure://localhost:9443")
            changed = True
            print("RECOVER: reasserted the approved private Serve route; existing native forward preserved")
        check_tailnet(project, tailscale)
    # An already-approved config with a missing listener is retried, not reset:
    # tailscaled already backs off and retries its own kernel listeners.
    with tailnet_lock(state_dir):
        retry(attempt, timeout=timeout)
    print("PASS: actual Tailnet sockets, tailscaled ownership and verified management HTTPS")


def inspect(project: Path | None = None) -> None:
    rows = boundary.interfaces()
    env = renderer().parse_env(project / ".env") if project is not None and (project / ".env").is_file() else {}
    tailnet_name = boundary.configured_tailnet_interface(env)
    tail = boundary.interface_ips(rows, tailnet_only=True, tailnet_name=tailnet_name)
    pid = boundary.tailscale_pid()
    for listener in boundary.listeners():
        owner = "tailscaled" if pid > 0 and listener.pids == {pid} else ("unknown (root required)" if not listener.pids else f"PIDs {sorted(listener.pids)}")
        print(f"TCP {listener.address} owner={owner}")
    print(f"Tailnet interface {tailnet_name} IPs: {', '.join(sorted(tail))}")
    print("UDP transport is separate from TCP HTTP/HTTPS:")
    print(boundary.command("ss", "-H", "-lunp").strip())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "check-public", "reconcile-public", "check-tailnet", "ensure-tailnet"))
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    project = args.project.resolve()
    try:
        docker = os.environ.get("DOCKER_BIN", "/usr/bin/docker")
        tailscale = os.environ.get("TAILSCALE_BIN", "/usr/bin/tailscale")
        if args.action == "inspect":
            inspect(project)
        elif args.action == "check-public":
            check_public(project, docker)
            print("PASS: running revision, listener ownership, health digest and ingress TLS verified")
        elif args.action == "reconcile-public":
            reconcile_public(project, docker, timeout=args.timeout)
        elif args.action == "check-tailnet":
            check_tailnet(project, tailscale)
        else:
            ensure_tailnet(project, tailscale, timeout=args.timeout)
    except (ValueError, OSError, subprocess.SubprocessError, http.client.HTTPException) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
