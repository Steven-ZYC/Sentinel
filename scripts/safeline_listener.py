#!/usr/bin/env python3
"""Validate/rebind every IPv4/IPv6 business listener with rollback."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from security_checks import addresses, assert_loopback, safeline_container

LISTEN = re.compile(r"^(\s*)listen\s+([^;\n]+);([^\n]*)$", re.M)


def listeners(content: str, port: int):
    for match in LISTEN.finditer(content):
        token = match[2].split()[0]
        if token == str(port) or token.endswith(f":{port}"):
            yield match


def rewrite(content: str, port: int) -> str:
    starts = {match.start() for match in listeners(content, port)}
    if not starts:
        raise ValueError(f"listener {port} not found")
    def replace(match):
        if match.start() not in starts:
            return match[0]
        tokens = match[2].split()
        ipv6 = tokens[0].startswith("[")
        tokens[0] = f"[::1]:{port}" if ipv6 else f"127.0.0.1:{port}"
        if not ipv6:
            tokens = [token for token in tokens if not token.startswith("ipv6only=")]
        return f"{match[1]}listen {' '.join(tokens)};{match[3]}"
    return LISTEN.sub(replace, content)


def atomic_write(path: Path, content: str) -> None:
    metadata = path.stat()
    descriptor, name = tempfile.mkstemp(prefix=".sentinel-listener-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), metadata.st_mode & 0o777)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    raw = os.environ.get("UPSTREAM_PORT", "10443")
    if not re.fullmatch(r"[0-9]{1,5}", raw) or not 1024 <= int(raw) <= 65535 or int(raw) == 9443:
        raise ValueError("UPSTREAM_PORT must be a valid distinct business port")
    port = int(raw)
    root = Path(os.environ.get("SAFELINE_DIR", "/data/safeline")).resolve()
    candidate = os.environ.get("SAFELINE_SITE_FILE")
    if candidate:
        path = Path(candidate).resolve()
        path.relative_to(root / "resources/nginx/sites-enabled")
    else:
        candidates = [path for path in (root / "resources/nginx/sites-enabled").glob("IF_*") if path.is_file() and list(listeners(path.read_text(), port))]
        if len(candidates) != 1:
            raise ValueError(f"expected exactly one SafeLine site for {port}; found {len(candidates)}")
        path = candidates[0]
    path = path.resolve(strict=True)
    path.relative_to(root / "resources/nginx/sites-enabled")
    content = path.read_text()
    if action == "check":
        configured = {match[2].split()[0] for match in listeners(content, port)}
        assert_loopback(port, configured)
        assert_loopback(port, addresses(port))
        print(f"OK: every configured and active listener for {port} is loopback-only")
        return
    if action not in ("apply", "restore") or os.geteuid() != 0:
        raise ValueError("usage: sudo safeline-listener.sh apply|restore [backup]; check is read-only")
    container = safeline_container(Path(__file__).resolve().parents[1])
    backup_root = root / "backups/sentinel/listeners"
    backup_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    backup_dir = Path(tempfile.mkdtemp(prefix="backup-", dir=backup_root))
    shutil.copy2(path, backup_dir / path.name)
    if action == "restore":
        backup = Path(sys.argv[2]).resolve()
        backup.relative_to(root / "backups/sentinel")
        new_content = backup.read_text()
    else:
        new_content = rewrite(content, port)
    try:
        atomic_write(path, new_content)
        subprocess.run(["docker", "exec", container, "nginx", "-t"], check=True, timeout=30)
        subprocess.run(["docker", "exec", container, "nginx", "-s", "reload"], check=True, timeout=30)
        for attempt in range(15):
            try:
                assert_loopback(port, addresses(port))
                break
            except ValueError:
                if attempt == 14:
                    raise
                time.sleep(1)
    except BaseException:
        atomic_write(path, content)
        subprocess.run(["docker", "exec", container, "nginx", "-t"], timeout=30, check=True)
        subprocess.run(["docker", "exec", container, "nginx", "-s", "reload"], timeout=30, check=True)
        raise
    print(f"Applied; recoverable backup: {backup_dir / path.name}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, IndexError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
