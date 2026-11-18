#!/usr/bin/env python3
"""Plan/apply scoped UFW rules without resetting SSH or unrelated rules."""
from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from security_checks import check_upstreams, renderer


def apply_command(command: list[str]) -> None:
    environment = {**os.environ, "LC_ALL": "C"}
    result = subprocess.run(command, check=True, timeout=30, capture_output=True, text=True, env=environment)
    print(result.stdout, end="")
    if re.search(r"Skipping (?:inserting|adding) existing rule", result.stdout):
        # UFW does not move duplicate rules. Delete only this exact related
        # interface/protocol/source/port rule, then reinsert it ahead of broad allows.
        if command[:3] != ["ufw", "insert", "1"] or command[-2] != "comment":
            raise ValueError("unexpected UFW command shape")
        subprocess.run(["ufw", "--force", "delete", *command[3:-2]], check=True, timeout=30, env=environment)
        result = subprocess.run(command, check=True, timeout=30, capture_output=True, text=True, env=environment)
        print(result.stdout, end="")
        if "Skipping" in result.stdout:
            raise ValueError("UFW could not put the scoped rule ahead of existing rules")


def firewall_rules(env: dict[str, str], sites: list) -> list[list[str]]:
    module = renderer()
    module.public_addresses(env)
    mode, cidrs, _ = module.edge_policy(env)
    interface = env.get("PUBLIC_INTERFACE", "")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface) or interface == "lo":
        raise ValueError("set PUBLIC_INTERFACE to the actual ingress interface (not assumed eth0)")
    ports = {9443, module.healthcheck_port(env, sites)} | {site.upstream_port for site in sites if isinstance(site, module.ProxySite)}
    if any(port < 1024 for port in ports):
        raise ValueError("business ports must be unprivileged; refusing to touch possible SSH ports")
    rules = [["deny", "in", "on", interface, "proto", "tcp", "to", "any", "port", str(port), "comment", "Sentinel private"] for port in sorted(ports)]
    if mode == "direct":
        rules.append(["allow", "in", "on", interface, "proto", "tcp", "to", "any", "port", "80,443", "comment", "Sentinel direct"])
    else:
        rules.extend(["allow", "in", "on", interface, "proto", "tcp", "from", cidr, "to", "any", "port", "80,443", "comment", "Sentinel trusted proxy"] for cidr in cidrs)
        rules.append(["deny", "in", "on", interface, "proto", "tcp", "to", "any", "port", "80,443", "comment", "Sentinel other peers"])
    return rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply"), default="plan", nargs="?")
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    project = args.project.resolve()
    module = renderer()
    env = module.parse_env(project / ".env")
    sites = module.load_sites(project / "sites.json")
    rules = firewall_rules(env, sites)
    # Reverse insert-at-1 order so trusted allow rules precede the fallback deny,
    # and pre-existing broad allow rules cannot override the new boundary.
    commands = [["ufw", "insert", "1", *rule] for rule in reversed(rules)]
    for command in commands:
        print(shlex.join(command))
    print("SSH and other rules are untouched; review cloud security groups and Docker DNAT separately.")
    if args.action == "plan":
        return
    if os.geteuid() != 0:
        raise ValueError("apply requires sudo")
    status = subprocess.check_output(["ufw", "status"], text=True, env={**os.environ, "LC_ALL": "C"}, timeout=30)
    if "Status: active" not in status:
        raise ValueError("UFW is inactive; configure SSH/out-of-band access and enable it manually first")
    subprocess.run(["ip", "link", "show", env["PUBLIC_INTERFACE"]], check=True, timeout=10)
    # A host firewall does not reliably protect Docker-published ports.
    check_upstreams(project)
    for command in commands:
        apply_command(command)
    print("PASS: scoped UFW rules applied; no reset, default policy change or SSH deletion")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
