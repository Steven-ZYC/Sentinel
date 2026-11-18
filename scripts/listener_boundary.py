"""Read-only, fail-closed socket ownership and final NGINX configuration checks."""
from __future__ import annotations

import ipaddress
import json
import re
import shlex
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


class UnsafeState(ValueError):
    """Do not change services in this state."""


class NotReady(ValueError):
    """A bounded retry may succeed without changing configuration."""


class MissingProxy(NotReady):
    pass


def command(*args: str, timeout: int = 8) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=timeout)


def endpoint(address: str, port: int) -> str:
    ip = ipaddress.ip_address(address.strip("[]"))
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


@dataclass(frozen=True)
class Listener:
    address: str
    pids: frozenset[int]
    detail: str


def parse_listeners(output: str) -> list[Listener]:
    result = []
    for row in output.splitlines():
        if not row.strip():
            continue
        columns = row.split()
        if len(columns) < 5 or columns[0] != "LISTEN":
            raise UnsafeState(f"unrecognised ss listener row: {row}")
        result.append(Listener(columns[3], frozenset(int(pid) for pid in re.findall(r"\bpid=(\d+)", row)), row))
    return result


def listeners(ports: set[int] | None = None) -> list[Listener]:
    if ports is None:
        return parse_listeners(command("ss", "-H", "-ltnp"))
    expression = "( " + " or ".join(f"sport = :{port}" for port in sorted(ports)) + " )"
    return parse_listeners(command("ss", "-H", "-ltnp", expression))


def interfaces() -> list[dict]:
    return json.loads(command("ip", "-j", "address", "show"))


def configured_tailnet_interface(env: dict[str, str] | None = None) -> str:
    name = (env or {}).get("TAILSCALE_INTERFACE") or "tailscale0"
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) or name == "lo":
        raise UnsafeState("TAILSCALE_INTERFACE must be a Linux TUN interface name (not lo)")
    return name


def interface_ips(rows: list[dict], *, tailnet_only: bool = False, tailnet_name: str = "tailscale0") -> set[str]:
    return {
        str(ipaddress.ip_address(item["local"]))
        for interface in rows if not tailnet_only or interface["ifname"] == tailnet_name
        for item in interface.get("addr_info", [])
        if not item.get("tentative") and not item.get("dadfailed")
        and (not tailnet_only or not ipaddress.ip_address(item["local"]).is_link_local)
    }


def assigned_public(public: list[str], env: dict[str, str], rows: list[dict]) -> None:
    tailnet_name = configured_tailnet_interface(env)
    tailnet = interface_ips(rows, tailnet_only=True, tailnet_name=tailnet_name)
    for value in public:
        ip = str(ipaddress.ip_address(value.strip("[]")))
        if ip in tailnet:
            raise UnsafeState(f"public listener {ip} overlaps {tailnet_name}")
        matches = [row for row in rows if ip in interface_ips([row])]
        if not matches:
            raise NotReady(f"public listener {ip} is not assigned locally (use the local ingress IP behind NAT)")
        selected = env.get("PUBLIC_INTERFACE", "")
        if selected and not any(selected in [row["ifname"], *row.get("altnames", [])] for row in matches):
            raise UnsafeState(f"public listener {ip} is not on PUBLIC_INTERFACE={selected}")
        if not any("UP" in row.get("flags", []) for row in matches):
            raise NotReady(f"interface for public listener {ip} is not UP")


def directives(text: str):
    # NGINX quotes/comments/escapes matter: a line-based regex misses split directives.
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";{}")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    current = []
    try:
        for token in lexer:
            if token and all(char in ";{}" for char in token):
                if current:
                    yield current
                    current = []
            else:
                current.append(token)
        if current:
            yield current
    except ValueError as error:
        raise UnsafeState(f"invalid quoted NGINX configuration: {error}") from error


def validate_listens(text: str, public: list[str], health_port: int) -> set[str]:
    approved = {endpoint(ip, port) for ip in public for port in (80, 443)} | {f"127.0.0.1:{health_port}"}
    found = set()
    for directive in directives(text):
        if directive[0] != "listen":
            continue
        if len(directive) < 2 or directive[1] not in approved:
            raise UnsafeState(f"unapproved NGINX listen directive: {' '.join(directive)}")
        if "udp" in directive or "ipv6only=off" in directive:
            raise UnsafeState("UDP/dual-stack wildcard listeners are forbidden")
        found.add(directive[1])
    return found


def validate_configuration(bootstrap: str, files: dict[str, str], public: list[str], health_port: int) -> None:
    expected_includes = [["include", "/etc/nginx/mime.types"], ["include", "/etc/nginx/conf.d/current/*.conf"]]
    actual = [row for row in directives(bootstrap) if row[0] == "include"]
    if actual != expected_includes or any(row[0] == "listen" for row in directives(bootstrap)):
        raise UnsafeState("NGINX bootstrap must include only mime.types and the atomic current revision; no bootstrap listeners")
    found = set()
    for name, content in files.items():
        if name.endswith(".conf"):
            if any(row[0] == "include" for row in directives(content)):
                raise UnsafeState(f"extra includes are forbidden in {name}")
            found |= validate_listens(content, public, health_port)
    required = {endpoint(ip, port) for ip in public for port in (80, 443)} | {f"127.0.0.1:{health_port}"}
    if found != required:
        raise UnsafeState(f"missing NGINX listeners: {sorted(required - found)}")


def validate_dump(dump: str, public: list[str], health_port: int, filenames: set[str]) -> None:
    loaded = re.findall(r"^# configuration file (.+):$", dump, re.MULTILINE)
    expected = {"/etc/nginx/nginx.conf", "/etc/nginx/mime.types"} | {f"/etc/nginx/conf.d/current/{name}" for name in filenames}
    if set(loaded) != expected:
        raise UnsafeState(f"unexpected/incomplete nginx -T include graph: {sorted(set(loaded) ^ expected)}")
    validate_listens(dump, public, health_port)


def inspect_proxy(project: Path, docker: str = "docker", *, recovery: bool = False) -> dict:
    try:
        results = json.loads(command(docker, "inspect", "sentinel-proxy"))
    except subprocess.CalledProcessError as error:
        if "No such object" in (error.stderr or "") or "No such container" in (error.stderr or ""):
            raise MissingProxy("sentinel-proxy is absent; automatic recovery never creates it") from error
        raise NotReady("Docker/container inspection unavailable; no container will be created or started") from error
    if len(results) != 1:
        raise UnsafeState("ambiguous sentinel-proxy inspection")
    proxy = results[0]
    labels = proxy.get("Config", {}).get("Labels") or {}
    if (labels.get("com.docker.compose.project") != "sentinel" or labels.get("com.docker.compose.service") != "proxy"
            or labels.get("com.docker.compose.project.working_dir") != str(project)):
        raise UnsafeState("sentinel-proxy does not belong to this Compose project")
    host = proxy.get("HostConfig", {})
    if host.get("NetworkMode") != "host" or host.get("RestartPolicy", {}).get("Name") != "unless-stopped":
        raise UnsafeState("unexpected network/restart policy; Docker must remain the lifecycle owner")
    for target, source in {"/etc/nginx/nginx.conf": project / "nginx/nginx.conf", "/etc/nginx/conf.d": project / "nginx/generated"}.items():
        mounts = [mount for mount in proxy.get("Mounts", []) if mount.get("Destination") == target]
        if len(mounts) != 1 or mounts[0].get("Source") != str(source) or mounts[0].get("RW", True):
            raise UnsafeState(f"unapproved Sentinel mount: {target}")
    if recovery and labels.get("io.sentinel.recovery") != "running-only":
        raise UnsafeState("container has not opted into bounded running-only recovery; redeploy first")
    if recovery:
        hooks = [mount for mount in proxy.get("Mounts", []) if mount.get("Destination") == "/usr/local/bin/sentinel-entrypoint"]
        if (proxy.get("Config", {}).get("Entrypoint") != ["/usr/local/bin/sentinel-entrypoint"] or len(hooks) != 1
                or hooks[0].get("Source") != "/usr/local/libexec/sentinel/container-startup-check.sh" or hooks[0].get("RW", True)):
            raise UnsafeState("verified startup hook is not installed in this container; redeploy first")
    if not re.fullmatch(r"[a-f0-9]{64}", proxy.get("Id", "")):
        raise UnsafeState("invalid inspected container identity")
    return proxy


def owned_by_proxy(pid: int, proxy: dict) -> bool:
    if pid == proxy.get("State", {}).get("Pid"):
        return True
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text()
    except OSError:
        return False
    return bool(re.search(rf"(?<![a-f0-9]){re.escape(proxy['Id'])}(?![a-f0-9])", cgroup))


def verified_root_daemon(directory: Path) -> bool:
    try:
        status = (directory / "status").read_text()
        if not re.search(r"^Uid:\s+0\s+0\s+\d+\s+\d+\s*$", status, re.MULTILINE):
            return False
        executable = directory / "exe"
        if executable.readlink().name.removesuffix(" (deleted)") != "tailscaled":
            return False
        info = executable.stat()
        return info.st_uid == 0 and stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022
    except OSError:
        return False


def tailscale_pid(proc_root: Path = Path("/proc")) -> int:
    try:
        pid = int(command("systemctl", "show", "tailscaled.service", "--property=MainPID", "--value").strip())
        if pid > 0:
            return pid
    except (ValueError, OSError, subprocess.SubprocessError):
        pass
    # OpenRC / non-systemd hosts: names alone are not sufficient. Require one
    # root daemon with the loaded, root-owned, non-writable tailscaled executable.
    deadline = time.monotonic() + 2
    candidates = []
    try:
        for directory in proc_root.iterdir():
            if time.monotonic() > deadline:
                return 0  # incomplete scan cannot establish uniqueness
            if directory.name.isdecimal() and verified_root_daemon(directory):
                candidates.append(int(directory.name))
                if len(candidates) > 1:
                    return 0  # never guess between multiple daemons/namespaces
    except OSError:
        return 0
    return candidates[0] if len(candidates) == 1 else 0


def require_owner(listener: Listener, predicate) -> None:
    if not listener.pids or not all(predicate(pid) for pid in listener.pids):
        raise UnsafeState(f"unapproved/unknown listener owner: {listener.detail}; inspect with sudo ss -ltnp")


def public_sockets(public: list[str], health_port: int, proxy: dict | None, rows: list[dict], *, required: bool, env: dict[str, str] | None = None) -> None:
    expected = {endpoint(ip, port) for ip in public for port in (80, 443)} | {f"127.0.0.1:{health_port}"}
    tailnet = {endpoint(ip, 443) for ip in interface_ips(rows, tailnet_only=True, tailnet_name=configured_tailnet_interface(env))}
    tail_pid = tailscale_pid() if tailnet else 0
    actual = listeners({80, 443, health_port})
    for listener in actual:
        if listener.address in expected:
            require_owner(listener, lambda pid: proxy is not None and owned_by_proxy(pid, proxy))
        elif listener.address in tailnet:
            require_owner(listener, lambda pid: pid == tail_pid and tail_pid > 0)
        else:
            raise UnsafeState(f"unexpected/wildcard listener: {listener.detail}")
    missing = expected - {listener.address for listener in actual}
    if required and missing:
        raise NotReady(f"Sentinel listeners not ready: {sorted(missing)}")
