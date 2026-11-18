#!/usr/bin/env python3
"""Stage, validate, explicitly reload and check the running revision; rollback on failure."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from security_checks import check_certificates, check_upstreams, renderer
from runtime_guard import preflight, check_public


def wait_revision(revision: Path, timeout: float = 50) -> None:
    port = int((revision / ".healthcheck-port").read_text())
    digest = (revision / ".config-digest").read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with opener.open(f"http://127.0.0.1:{port}/.sentinel/health", timeout=2) as response:
                if response.status == 200 and response.read(64) == b"ok\n" and response.headers.get("X-Sentinel-Config") == digest:
                    return
        except OSError:
            pass
        time.sleep(1)
    raise ValueError("running NGINX did not serve the newly published configuration digest")


def install_startup_hook(project: Path) -> None:
    if os.geteuid() != 0:
        raise ValueError("sudo deploy is required to install the root-owned startup hook; no production container was changed")
    subprocess.run(["bash", str(project / "scripts/install-guard-code.sh")], check=True, timeout=30)


def deploy(project: Path, *, check_only: bool = False) -> None:
    module = renderer()
    env = module.parse_env(project / ".env")
    sites = module.load_sites(project / "sites.json")
    root = module.parse_tls_mount_root(env)
    tls = module.parse_default_tls(env)
    files = module.rendered_files(module.parse_public_address(env), root, tls, sites, env)
    preflight(project, files, env)
    check_upstreams(project)
    check_certificates(project)
    output = project / "nginx/generated"
    output.mkdir(parents=True, exist_ok=True)
    compose = ["docker", "compose", "--project-directory", str(project), "--env-file", str(project / ".env"), "-f", str(project / "compose.yaml")]
    def execute(*args, **kwargs):
        return subprocess.run(args, check=True, timeout=180, env={**os.environ, "TLS_MOUNT_ROOT": root}, **kwargs)
    with (output / ".publish.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = (output / "current").resolve() if (output / "current").is_symlink() else None
        candidate = module.stage_rendered_files(output, files)
        with tempfile.TemporaryDirectory(prefix="sentinel-deploy-") as temporary:
            staging = Path(temporary)
            staging.chmod(0o755)
            bootstrap = (project / "nginx/nginx.conf").read_text()
            include = "include /etc/nginx/conf.d/current/*.conf;"
            if bootstrap.count(include) != 1:
                raise ValueError("NGINX bootstrap must include exactly the atomic current revision")
            test_config = staging / "candidate.conf"
            test_config.write_text(bootstrap.replace(include, f"include /etc/nginx/conf.d/.revisions/{candidate.name}/*.conf;"))
            test_config.chmod(0o644)
            execute(*compose, "config", "--quiet")
            execute(*compose, "run", "--rm", "--no-deps", "--entrypoint", "nginx", "--volume", f"{test_config}:/etc/nginx/nginx.conf:ro",
                    "--volume", f"{project / 'scripts/container-startup-check.sh'}:/usr/local/bin/sentinel-entrypoint:ro", "proxy", "-t")
            if check_only:
                print(f"PASS: complete candidate validated without activating it: {candidate}")
                return
            inspected = subprocess.run(["docker", "inspect", "sentinel-proxy"], text=True, capture_output=True, timeout=30)
            old = json.loads(inspected.stdout)[0] if inspected.returncode == 0 else None
            rollback_compose = None
            def rollback_service(snapshot: Path) -> dict:
                volumes = []
                for mount in old.get("Mounts", []):
                    if mount["Type"] in ("bind", "volume") and mount["Destination"] != "/etc/nginx/nginx.conf":
                        volumes.append({"type": mount["Type"], "source": mount.get("Name") if mount["Type"] == "volume" else mount["Source"], "target": mount["Destination"], "read_only": not mount.get("RW", False)})
                volumes.append(f"{snapshot}:/etc/nginx/nginx.conf:ro")
                service = {"image": old["Config"]["Image"], "volumes": volumes}
                # Do not run the new checksum hook against a legacy bootstrap.
                service["entrypoint"] = old["Config"].get("Entrypoint") or ["/docker-entrypoint.sh"]
                if old["Config"].get("Cmd"):
                    service["command"] = old["Config"]["Cmd"]
                health = old["Config"].get("Healthcheck")
                if health:
                    service["healthcheck"] = {"test": health["Test"]}
                    for docker_key, compose_key in (("Interval", "interval"), ("Timeout", "timeout"), ("StartPeriod", "start_period"), ("StartInterval", "start_interval")):
                        if health.get(docker_key):
                            service["healthcheck"][compose_key] = f"{health[docker_key]}ns"
                    if health.get("Retries"):
                        service["healthcheck"]["retries"] = health["Retries"]
                return service
            if old:
                saved = subprocess.check_output(["docker", "exec", "sentinel-proxy", "cat", "/etc/nginx/nginx.conf"], text=True, timeout=30)
                # Upgrade from flat files retains those files untouched for first-deploy rollback.
                if previous is None:
                    saved = saved.replace(include, "include /etc/nginx/conf.d/*.conf;")
                rollback_config = staging / "rollback.conf"
                rollback_config.write_text(saved)
                rollback_config.chmod(0o644)
                rollback_override = staging / "rollback-compose.json"
                rollback_override.write_text(json.dumps({"services": {"proxy": rollback_service(rollback_config)}}))
                rollback_compose = compose + ["-f", str(rollback_override)]
            preflight(project, files, env)
            install_startup_hook(project)
            try:
                module.activate_revision(output, candidate)
                # Recreate deliberately: changed bind-mounted bootstrap/image must not stay stale.
                execute(*compose, "up", "-d", "--force-recreate", "--no-deps", "proxy")
                execute(*compose, "exec", "-T", "proxy", "nginx", "-t")
                execute(*compose, "exec", "-T", "proxy", "nginx", "-s", "reload")
                wait_revision(candidate)
                check_public(project)
                check_upstreams(project)
            except BaseException:
                print("ERROR: publication failed; restoring the prior configuration and image", file=sys.stderr)
                if previous:
                    module.activate_revision(output, previous)
                else:
                    (output / "current").unlink(missing_ok=True)
                if rollback_compose:
                    # Persist the snapshot: the rollback bind mount must survive this process.
                    rollback_dir = output / ".rollback"
                    rollback_dir.mkdir(mode=0o755, exist_ok=True)
                    snapshot = rollback_dir / f"{candidate.name}-bootstrap.conf"
                    snapshot.write_text(rollback_config.read_text())
                    snapshot.chmod(0o644)
                    override = rollback_dir / f"{candidate.name}-compose.json"
                    override.write_text(json.dumps({"services": {"proxy": rollback_service(snapshot)}}))
                    execute(*compose, "-f", str(override), "up", "-d", "--force-recreate", "--no-deps", "proxy")
                    execute(*compose, "-f", str(override), "exec", "-T", "proxy", "nginx", "-t")
                    if previous:
                        wait_revision(previous)
                elif old is None:
                    execute(*compose, "stop", "proxy")
                raise
            print(f"PASS: running configuration digest verified; revision {candidate.name}")
            print(f"Previous revision retained: {previous or 'legacy flat files'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        deploy(args.project.resolve(), check_only=args.check_only)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
