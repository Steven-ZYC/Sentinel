#!/usr/bin/env python3
"""Scoped local hardening. Root required; never reset firewall or change DNS."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from security_checks import check_upstreams, renderer, safeline_container
from safeline_listener import atomic_write


def harden_tls(project: Path) -> None:
    module = renderer()
    env = module.parse_env(project / ".env")
    root = Path(module.parse_tls_mount_root(env)).resolve()
    if len(root.parts) < 4 or root == project or root in project.parents:
        raise ValueError("TLS_MOUNT_ROOT must be a dedicated certificate directory, not a broad directory")
    for parent in root.parents:
        metadata = parent.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError(f"TLS directory needs root-owned, non-writable ancestors (use /etc or /data): {parent}")
    sites = module.load_sites(project / "sites.json")
    pairs = [module.parse_default_tls(env)] + [site.tls for site in sites]
    files = {}
    directories = {root}
    for tls in pairs:
        module.container_tls(tls, str(root))
        for path, mode in ((Path(tls.certificate), 0o644), (Path(tls.private_key), 0o600)):
            path = path.resolve(strict=True)
            path.relative_to(root)
            if not path.is_file():
                raise ValueError(f"certificate material is not a regular file: {path}")
            files[path] = min(mode, files.get(path, mode))
            parent = path.parent
            while parent != root:
                directories.add(parent)
                parent = parent.parent
    # Validate all targets before changing any permission; no recursive broad chmod.
    # Lock ancestors first, then use no-follow descriptors. A previously writable
    # certificate directory must not allow a symlink swap into arbitrary root files.
    for directory in sorted(directories, key=lambda path: len(path.parts)):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o750)
        finally:
            os.close(descriptor)
    for path, mode in files.items():
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError(f"TLS target must be a regular file with one link: {path}")
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
    module.validate_certificates(str(root), pairs[0], sites)
    print("OK: declared TLS keys root:root 0600; certificate directories 0750")


def archive_backups(target: Path, backup_root: Path) -> Path:
    target = target.resolve(strict=True)
    backup_root = backup_root.resolve()
    if target == backup_root or target in backup_root.parents or len(target.parts) < 4 or len(backup_root.parts) < 4:
        raise ValueError("backup directory must be outside a dedicated webroot")
    backup_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    backup_root.chmod(0o700)
    destination = Path(tempfile.mkdtemp(prefix="webroot-", dir=backup_root))
    backups = list(target.glob("index.html.pre-split-*"))
    for path in backups:
        if not re.fullmatch(r"index\.html\.pre-split-[A-Za-z0-9_-]+", path.name) or path.is_symlink() or not path.is_file():
            raise ValueError(f"refusing unexpected backup path: {path}")
    for path in backups:
        shutil.move(str(path), str(destination / path.name))
        (destination / path.name).chmod(0o600)
    print(f"OK: legacy public backups moved to recoverable private directory: {destination}")
    return destination


def install_realip(project: Path, safeline_root: Path) -> None:
    check_upstreams(project)
    destination = safeline_root / "resources/nginx/conf.d/_sentinel_realip.conf"
    source = (project / "safeline/sentinel-realip.conf").read_text()
    previous = destination.read_text() if destination.exists() else None
    if not destination.exists():
        destination.touch(mode=0o644)
    atomic_write(destination, source)
    destination.chmod(0o644)
    container = safeline_container(project)
    try:
        subprocess.run(["docker", "exec", container, "nginx", "-t"], check=True, timeout=30)
        subprocess.run(["docker", "exec", container, "nginx", "-s", "reload"], check=True, timeout=30)
    except BaseException:
        if previous is None:
            destination.unlink(missing_ok=True)
        else:
            atomic_write(destination, previous)
        subprocess.run(["docker", "exec", container, "nginx", "-t"], check=True, timeout=30)
        subprocess.run(["docker", "exec", container, "nginx", "-s", "reload"], check=True, timeout=30)
        raise
    print("OK: SafeLine trusts only Sentinel loopback for canonical client IP")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("tls", "backups", "realip"))
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--safeline", type=Path, default=Path(os.environ.get("SAFELINE_DIR", "/data/safeline")))
    parser.add_argument("--webroot", type=Path)
    parser.add_argument("--backup-root", type=Path)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("run with sudo; no root-owned target was modified")
        if args.action == "tls":
            harden_tls(args.project.resolve())
        elif args.action == "realip":
            install_realip(args.project.resolve(), args.safeline.resolve())
        else:
            archive_backups(args.webroot or args.safeline / "resources/nginx/static/static_1", args.backup_root or args.safeline / "backups/sentinel/site")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
