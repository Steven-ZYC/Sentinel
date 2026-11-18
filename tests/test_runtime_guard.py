"""Read-only / mocked lifecycle tests plus real, isolated shell/socket tests.

These do not reboot the host, restart Docker/Tailscale or bind production ports.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import socket
import shutil
import subprocess
import sys
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_render_sites as fixtures

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import listener_boundary as boundary
import runtime_guard as guard
import security_checks

PUBLIC = ["203.0.113.10"]
TAIL = ["100.100.100.100", "fd7a:115c:a1e0::10"]
TAIL_PID = 1234
PROXY_PID = 4321
PROXY_ID = "a" * 64
SERVE = {"TCP": {"443": {"HTTPS": True}}, "Web": {"node.example.ts.net:443": {"Handlers": {"/": {"Proxy": "https+insecure://localhost:9443"}}}}}


def listener(address, pid=PROXY_PID):
    pids = frozenset() if pid is None else frozenset({pid})
    return boundary.Listener(address, pids, f"{address} pid={pid}")


def interfaces():
    return [
        {"ifname": "eth0", "altnames": ["ens3"], "flags": ["UP"], "addr_info": [{"local": PUBLIC[0]}]},
        {"ifname": "tailscale0", "flags": ["UP"], "addr_info": [{"local": ip} for ip in TAIL]},
    ]


def proxy(project):
    return {
        "Id": PROXY_ID,
        "Config": {"Entrypoint": ["/usr/local/bin/sentinel-entrypoint"], "Labels": {"com.docker.compose.project": "sentinel", "com.docker.compose.service": "proxy", "com.docker.compose.project.working_dir": str(project), "io.sentinel.recovery": "running-only"}},
        "HostConfig": {"NetworkMode": "host", "RestartPolicy": {"Name": "unless-stopped"}},
        "Mounts": [{"Destination": target, "Source": str(project / source), "RW": False} for target, source in (("/etc/nginx/nginx.conf", "nginx/nginx.conf"), ("/etc/nginx/conf.d", "nginx/generated"))] + [{"Destination": "/usr/local/bin/sentinel-entrypoint", "Source": "/usr/local/libexec/sentinel/container-startup-check.sh", "RW": False}],
        "State": {"Pid": PROXY_PID, "Running": True, "Restarting": False, "Health": {"Status": "healthy"}},
    }


class ListenerPolicyTests(unittest.TestCase):
    def test_ss_parser_retains_all_owners_and_unknowns(self):
        rows = boundary.parse_listeners('LISTEN 0 511 203.0.113.10:443 0.0.0.0:* users:(("nginx",pid=42,fd=8),("nginx",pid=43,fd=8))\nLISTEN 0 4096 [fd7a:115c:a1e0::10]:443 [::]:*\n')
        self.assertEqual(rows[0].pids, {42, 43})
        self.assertFalse(rows[1].pids)

    def test_wrong_pid_or_unknown_owner_fails_closed(self):
        for pid in (None, TAIL_PID):
            with self.subTest(pid=pid), self.assertRaises(boundary.UnsafeState):
                boundary.require_owner(listener("203.0.113.10:443", pid), lambda owner: owner == PROXY_PID)

    def test_assignment_accepts_nat_and_interface_alias(self):
        boundary.assigned_public(PUBLIC, {"PUBLIC_INTERFACE": "ens3"}, interfaces())
        rows = [{"ifname": "ens3", "flags": ["UP"], "addr_info": [{"local": "10.0.0.5"}]}]
        boundary.assigned_public(["10.0.0.5"], {}, rows)

    def test_public_tailnet_overlap_wrong_interface_and_missing_address(self):
        with self.assertRaises(boundary.UnsafeState):
            boundary.assigned_public([TAIL[0]], {}, interfaces())
        with self.assertRaises(boundary.UnsafeState):
            boundary.assigned_public(PUBLIC, {"PUBLIC_INTERFACE": "eth9"}, interfaces())
        with self.assertRaises(boundary.NotReady):
            boundary.assigned_public(PUBLIC, {}, [])

    def test_missing_tailnet_listener_is_not_a_passing_serve_config(self):
        with patch.object(boundary, "listeners", return_value=[listener("127.0.0.1:9443")]), self.assertRaises(boundary.NotReady):
            guard.tailnet_sockets(SERVE, TAIL, TAIL_PID, required=True)

    def test_all_assigned_tailnet_addresses_and_native_forward_required(self):
        rows = [listener("127.0.0.1:9443"), *[listener(boundary.endpoint(ip, 443), TAIL_PID) for ip in TAIL]]
        with patch.object(boundary, "listeners", return_value=rows):
            guard.tailnet_sockets(SERVE, TAIL, TAIL_PID, required=True)
            native = {**SERVE, "TCP": {**SERVE["TCP"], "9443": {"TCPForward": "127.0.0.1:9443"}}}
            with self.assertRaises(boundary.NotReady):
                guard.tailnet_sockets(native, TAIL, TAIL_PID, required=True)

    def test_unapproved_owner_wildcard_and_public_management_not_repaired(self):
        for row in (listener(boundary.endpoint(TAIL[0], 443)), listener("0.0.0.0:443", TAIL_PID), listener("[::]:443", TAIL_PID), listener("203.0.113.10:9443"), listener("203.0.113.10:443", TAIL_PID)):
            with self.subTest(row=row.address), patch.object(boundary, "listeners", return_value=[listener("127.0.0.1:9443"), row]), self.assertRaises(boundary.UnsafeState):
                guard.tailnet_sockets(SERVE, TAIL, TAIL_PID, required=False)

    def test_services_config_is_not_silently_treated_as_empty(self):
        with self.assertRaises(ValueError):
            security_checks.assert_serve({"Services": {"svc:example": {}}}, allow_empty=True)

    def test_custom_tailnet_interface_cannot_be_used_as_public_ingress(self):
        rows = [{"ifname": "ts-vpn0", "flags": ["UP"], "addr_info": [{"local": TAIL[0]}]}]
        with self.assertRaises(boundary.UnsafeState):
            boundary.assigned_public([TAIL[0]], {"TAILSCALE_INTERFACE": "ts-vpn0"}, rows)

    def test_invalid_tailnet_interface_names_rejected(self):
        self.assertEqual(boundary.configured_tailnet_interface({}), "tailscale0")
        for name in ("lo", "../tailscale0", "ts vpn", "ts0\neth0", "a" * 16, "userspace-networking"):
            with self.subTest(name=name), self.assertRaises(boundary.UnsafeState):
                boundary.configured_tailnet_interface({"TAILSCALE_INTERFACE": name})

    def test_two_addresses_share_a_port_in_either_startup_order(self):
        for order in (("127.0.0.1", "127.0.0.2"), ("127.0.0.2", "127.0.0.1")):
            with self.subTest(order=order), socket.socket() as first, socket.socket() as second:
                first.bind((order[0], 0))
                first.listen()
                second.bind((order[1], first.getsockname()[1]))
                second.listen()

    def test_wildcard_overlaps_specific_socket(self):
        with socket.socket() as first, socket.socket() as second:
            first.bind(("127.0.0.2", 0))
            first.listen()
            with self.assertRaises(OSError):
                second.bind(("0.0.0.0", first.getsockname()[1]))


class RuntimeGuardTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RenderSitesTests()
        self.fixture.setUp()
        self.project = self.fixture.root
        (self.project / "nginx").mkdir()
        (self.project / "nginx/nginx.conf").write_text((ROOT / "nginx/nginx.conf").read_text())
        module = security_checks.renderer()
        self.env = module.parse_env(self.fixture.env)
        self.sites = module.load_sites(self.fixture.sites)
        self.files = module.rendered_files(PUBLIC[0], str(self.project), module.parse_default_tls(self.env), self.sites, self.env)
        module.write_rendered_files(self.project / "nginx/generated", self.files)
        self.current = (self.project / "nginx/generated/current").resolve()
        self.proxy = proxy(self.project)

    def tearDown(self):
        self.fixture.tearDown()

    def test_current_revision_is_checked_not_current_current(self):
        result = guard.checked_revision(self.project)
        self.assertEqual(result[-1], self.current)

    def test_other_servers_public_ipv4_and_interfaces_share_443_safely(self):
        module = security_checks.renderer()
        servers = [
            ("198.51.100.24", "ens18", "tailscale0", "100.70.2.3", "fd7a:115c:a1e0::23"),
            ("192.0.2.81", "enp5s0", "ts-vpn0", "100.89.6.7", "fd7a:115c:a1e0::67"),
            ("203.0.113.99", "bond0.7", "tailnet0", "100.99.88.22", "fd7a:115c:a1e0::8822"),
            ("198.51.100.60", "tailscale-wan", "tailscale0", "100.87.5.4", "fd7a:115c:a1e0::54"),
        ]
        for public, physical, tailnet, tail4, tail6 in servers:
            with self.subTest(server=public):
                env = {**self.env, "PUBLIC_LISTEN_ADDR": public, "PUBLIC_INTERFACE": physical, "TAILSCALE_INTERFACE": tailnet}
                files = module.rendered_files(public, str(self.project), module.parse_default_tls(env), self.sites, env)
                self.assertEqual(files[".public-listen-addresses"], public + "\n")
                self.assertEqual(files[".tailscale-interface"], tailnet + "\n")
                boundary.validate_configuration((ROOT / "nginx/nginx.conf").read_text(), files, [public], 18090)
                rows = [
                    {"ifname": physical, "flags": ["UP"], "addr_info": [{"local": public}]},
                    {"ifname": tailnet, "flags": ["UP"], "addr_info": [{"local": tail4}, {"local": tail6}]},
                ]
                boundary.assigned_public([public], env, rows)
                sockets = [listener(boundary.endpoint(public, port)) for port in (80, 443)] + [listener("127.0.0.1:18090")]
                sockets += [listener(boundary.endpoint(ip, 443), TAIL_PID) for ip in (tail4, tail6)]
                with patch.object(boundary, "listeners", return_value=sockets), patch.object(boundary, "tailscale_pid", return_value=TAIL_PID):
                    boundary.public_sockets([public], 18090, self.proxy, rows, required=True, env=env)
                for blocked in (listener(f"{public}:80", TAIL_PID), listener(f"{public}:443", TAIL_PID), listener("0.0.0.0:443", TAIL_PID), listener("[::]:443", TAIL_PID)):
                    with patch.object(boundary, "listeners", return_value=[*sockets, blocked]), patch.object(boundary, "tailscale_pid", return_value=TAIL_PID), self.assertRaises(boundary.UnsafeState):
                        boundary.public_sockets([public], 18090, self.proxy, rows, required=False, env=env)

    def test_public_ingress_does_not_wait_for_tailscale_to_create_its_interface(self):
        public = "198.51.100.42"
        env = {"PUBLIC_LISTEN_ADDR": public, "PUBLIC_INTERFACE": "ens18", "TAILSCALE_INTERFACE": "ts-vpn0"}
        rows = [{"ifname": "ens18", "flags": ["UP"], "addr_info": [{"local": public}]}]
        boundary.assigned_public([public], env, rows)
        sockets = [listener(f"{public}:{port}") for port in (80, 443)] + [listener("127.0.0.1:18090")]
        with patch.object(boundary, "listeners", return_value=sockets), patch.object(boundary, "tailscale_pid") as pid:
            boundary.public_sockets([public], 18090, self.proxy, rows, required=True, env=env)
        pid.assert_not_called()

    def test_non_systemd_host_requires_one_verified_root_tailscale_daemon(self):
        proc = self.project / "mock-proc"
        proc.mkdir()
        (proc / "101").mkdir()
        (proc / "202").mkdir()
        failure = subprocess.CalledProcessError(1, ["systemctl"])
        with patch.object(boundary, "command", side_effect=failure), patch.object(boundary, "verified_root_daemon", side_effect=lambda directory: directory.name == "101"):
            self.assertEqual(boundary.tailscale_pid(proc), 101)
        with patch.object(boundary, "command", side_effect=failure), patch.object(boundary, "verified_root_daemon", return_value=True):
            self.assertEqual(boundary.tailscale_pid(proc), 0)

    def test_root_daemon_verification_rejects_unprivileged_name_spoofing(self):
        directory = self.project / "mock-process"
        directory.mkdir()
        (directory / "status").write_text("Name:\ttailscaled\nUid:\t1000\t1000\t1000\t1000\n")
        self.assertFalse(boundary.verified_root_daemon(directory))
        (directory / "status").write_text("Name:\ttailscaled\nUid:\t0\t0\t0\t0\n")
        (directory / "exe").symlink_to("/usr/bin/python3")
        self.assertFalse(boundary.verified_root_daemon(directory))

    def test_loaded_daemon_verification_handles_package_replacement_safely(self):
        for uid, mode, expected in ((0, 0o100755, True), (1000, 0o100755, False), (0, 0o100775, False)):
            with self.subTest(uid=uid, mode=mode), patch.object(Path, "read_text", return_value="Uid:\t0\t0\t0\t0\n"), patch.object(Path, "readlink", return_value=Path("/usr/sbin/tailscaled (deleted)")), patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=uid, st_mode=mode)):
                self.assertEqual(boundary.verified_root_daemon(Path("/proc/12345")), expected)

    def test_systemd_daemon_identity_takes_precedence_over_proc_scan(self):
        with patch.object(boundary, "command", return_value="606\n"), patch.object(boundary, "verified_root_daemon") as verify:
            self.assertEqual(boundary.tailscale_pid(), 606)
        verify.assert_not_called()

    def test_tailnet_identity_uses_this_servers_configured_tun(self):
        with (self.fixture.env).open("a") as stream:
            stream.write("TAILSCALE_INTERFACE=ts-vpn0\n")
        rows = interfaces()
        rows[1]["ifname"] = "ts-vpn0"
        status = {"BackendState": "Running", "Self": {"TailscaleIPs": TAIL, "DNSName": "node.example.ts.net."}}
        with patch.object(boundary, "command", side_effect=[json.dumps(SERVE), json.dumps(status)]), patch.object(boundary, "interfaces", return_value=rows), patch.object(boundary, "tailscale_pid", return_value=TAIL_PID):
            state, ips, hostname, pid = guard.tailnet_state(self.project, "tailscale")
        self.assertEqual(ips, TAIL)
        self.assertEqual(hostname, "node.example.ts.net")
        self.assertEqual(pid, TAIL_PID)

    def test_bootstrap_and_all_included_files_checked(self):
        bootstrap = (self.project / "nginx/nginx.conf").read_text()
        boundary.validate_configuration(bootstrap, self.files, PUBLIC, 18090)
        for bad in ("server { listen\n443 ssl; }", 'server { listen "0.0.0.0:443" ssl; }', "server { listen [::]:443 ipv6only=off; }", "include /etc/nginx/legacy/*.conf;", "server { listen 203.0.113.10:443; include hidden.conf; }"):
            with self.subTest(bad=bad), self.assertRaises(boundary.UnsafeState):
                boundary.validate_configuration(bootstrap, {**self.files, "99-extra.conf": bad}, PUBLIC, 18090)
        with self.assertRaises(boundary.UnsafeState):
            boundary.validate_configuration(bootstrap + "\ninclude /etc/nginx/legacy/*.conf;", self.files, PUBLIC, 18090)

    def test_dump_requires_the_complete_approved_include_graph(self):
        names = {name for name in self.files if name.endswith(".conf")}
        loaded = ["/etc/nginx/nginx.conf", "/etc/nginx/mime.types", *[f"/etc/nginx/conf.d/current/{name}" for name in names]]
        dump = "\n".join(f"# configuration file {name}:\n" for name in loaded)
        boundary.validate_dump(dump, PUBLIC, 18090, names)
        with self.assertRaises(boundary.UnsafeState):
            boundary.validate_dump(dump + "# configuration file /etc/nginx/legacy.conf:\nlisten 443;", PUBLIC, 18090, names)

    def test_manifest_has_no_self_checksum_and_covers_every_file(self):
        entries = self.files[".startup-checksums"].splitlines()
        self.assertFalse(any(line.endswith("/.startup-checksums") for line in entries))
        for name, content in self.files.items():
            if name != ".startup-checksums":
                self.assertIn(f"{hashlib.sha256(content.encode()).hexdigest()}  /etc/nginx/conf.d/current/{name}", entries)

    def test_inspection_refuses_foreign_container_or_missing_recovery_opt_in(self):
        with patch.object(boundary, "command", return_value=json.dumps([self.proxy])):
            self.assertEqual(boundary.inspect_proxy(self.project, recovery=True)["Id"], PROXY_ID)
        for key, value in (("com.docker.compose.project.working_dir", "/another/repo"), ("io.sentinel.recovery", "disabled")):
            invalid = json.loads(json.dumps(self.proxy))
            invalid["Config"]["Labels"][key] = value
            with patch.object(boundary, "command", return_value=json.dumps([invalid])), self.assertRaises(boundary.UnsafeState):
                boundary.inspect_proxy(self.project, recovery=True)

    def test_public_and_tailnet_owners_are_not_interchangeable(self):
        rows = [listener(boundary.endpoint(PUBLIC[0], port)) for port in (80, 443)] + [listener("127.0.0.1:18090")] + [listener(boundary.endpoint(ip, 443), TAIL_PID) for ip in TAIL]
        with patch.object(boundary, "listeners", return_value=rows), patch.object(boundary, "tailscale_pid", return_value=TAIL_PID):
            boundary.public_sockets(PUBLIC, 18090, self.proxy, interfaces(), required=True)
        for bad in (listener("203.0.113.10:443", TAIL_PID), listener("203.0.113.10:443", None), listener("0.0.0.0:443", TAIL_PID)):
            with self.subTest(bad=bad), patch.object(boundary, "listeners", return_value=[*rows, bad]), patch.object(boundary, "tailscale_pid", return_value=TAIL_PID), self.assertRaises(boundary.UnsafeState):
                boundary.public_sockets(PUBLIC, 18090, self.proxy, interfaces(), required=False)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not installed")
    def test_unit_syntax_without_installing_production_services(self):
        units = self.project / "unit-validation"
        units.mkdir()
        paths = []
        for source in (ROOT / "systemd").glob("*.service"):
            target = units / source.name
            # Only stub not-yet-installed executable paths; preserve dependencies,
            # timers, timeouts and every other service setting. No unit is started.
            text = source.read_text().replace("/usr/local/libexec/sentinel/sentinel-runtime-guard", "/usr/bin/true").replace("/usr/local/libexec/sentinel/tailscale-sentinel-guard", "/usr/bin/true")
            target.write_text(text)
            paths.append(str(target))
        for source in (ROOT / "systemd").glob("*.timer"):
            target = units / source.name
            target.write_text(source.read_text())
            paths.append(str(target))
        result = subprocess.run(["systemd-analyze", "verify", *paths], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_installed_guard_uses_a_protected_code_snapshot_not_the_checkout(self):
        wrapper = (ROOT / "scripts/sentinel-runtime-guard.sh").read_text()
        self.assertIn('"$GUARD_DIR/scripts/runtime_guard.py"', wrapper)
        self.assertNotIn('exec /usr/bin/python3 "$PROJECT_DIR/', wrapper)
        installer = (ROOT / "scripts/install-guard-code.sh").read_text()
        self.assertIn("-o root -g root -m 0644", installer)

    def public_patches(self):
        stack = ExitStack()
        stack.enter_context(patch.object(guard, "root_only"))
        stack.enter_context(patch.object(boundary, "interfaces", return_value=interfaces()))
        stack.enter_context(patch.object(boundary, "inspect_proxy", return_value=self.proxy))
        stack.enter_context(patch.object(boundary, "public_sockets"))
        stack.enter_context(patch.object(boundary, "validate_dump"))
        stack.enter_context(patch.object(guard, "check_upstreams"))
        stack.enter_context(patch.object(security_checks.renderer(), "validate_certificates"))
        stack.enter_context(patch.object(guard.time, "sleep"))
        return stack

    def test_one_verified_public_restart_and_no_tailscale_command(self):
        with self.public_patches(), patch.object(guard, "check_public", side_effect=[boundary.NotReady("stale digest"), None]), patch.object(guard, "recovery_slot") as slot, patch.object(boundary, "command", return_value="") as command:
            guard.reconcile_public(self.project)
        restarts = [call.args for call in command.call_args_list if "restart" in call.args]
        self.assertEqual(restarts, [("docker", "restart", "--time", "10", PROXY_ID)])
        self.assertFalse(any("tailscale" in part for call in command.call_args_list for part in call.args))
        slot.assert_called_once()

    def test_stopped_paused_starting_or_docker_restarting_never_started(self):
        for change in ({"Running": False}, {"Paused": True}, {"Restarting": True}, {"Health": {"Status": "starting"}}):
            self.proxy["State"] = {"Pid": PROXY_PID, "Running": True, **change}
            with self.subTest(change=change), self.public_patches(), patch.object(guard, "check_public", side_effect=boundary.NotReady("down")), patch.object(boundary, "command") as command, self.assertRaises(ValueError):
                guard.reconcile_public(self.project, timeout=0.01)
            self.assertFalse(any("restart" in call.args or "start" in call.args for call in command.call_args_list))

    def test_port_conflict_unknown_owner_and_configuration_drift_never_restarted(self):
        with self.public_patches(), patch.object(guard, "check_public", side_effect=boundary.UnsafeState("foreign PID")), patch.object(boundary, "command") as command, self.assertRaises(boundary.UnsafeState):
            guard.reconcile_public(self.project)
        command.assert_not_called()
        (self.current / "10-app.conf").write_text("server { listen 443; }")
        with self.public_patches(), patch.object(guard, "check_public", side_effect=boundary.NotReady("down")), patch.object(boundary, "command") as command, self.assertRaises(ValueError):
            guard.reconcile_public(self.project)
        command.assert_not_called()

    def test_missing_address_retried_without_restart_until_it_returns(self):
        with self.public_patches(), patch.object(guard, "check_public", side_effect=[boundary.NotReady("address missing"), None]), patch.object(boundary, "assigned_public", side_effect=boundary.NotReady("waiting for DHCP")), patch.object(boundary, "command") as command:
            guard.reconcile_public(self.project)
        command.assert_not_called()

    def test_cooldown_does_not_issue_another_restart(self):
        with self.public_patches(), patch.object(guard, "check_public", side_effect=boundary.NotReady("down")), patch.object(guard, "recovery_slot", side_effect=boundary.NotReady("cooldown")), patch.object(boundary, "command", return_value="") as command, self.assertRaises(boundary.NotReady):
            guard.reconcile_public(self.project, timeout=0.01)
        self.assertFalse(any("restart" in call.args for call in command.call_args_list))

    def test_container_replacement_race_does_not_target_the_new_name(self):
        replacement = json.loads(json.dumps(self.proxy))
        replacement["Id"] = "b" * 64
        with self.public_patches(), patch.object(guard, "check_public", side_effect=[boundary.NotReady("down"), None]), patch.object(boundary, "inspect_proxy", side_effect=[self.proxy, replacement]), patch.object(boundary, "command", return_value="") as command:
            guard.reconcile_public(self.project)
        self.assertFalse(any("restart" in call.args for call in command.call_args_list))

    def test_publication_lock_prevents_recovery_during_deploy(self):
        with (self.project / "nginx/generated/.publish.lock").open("a") as locked:
            fcntl.flock(locked, fcntl.LOCK_EX)
            with patch.object(guard, "root_only"), patch.object(boundary, "command") as command, self.assertRaises(boundary.NotReady):
                guard.reconcile_public(self.project)
        command.assert_not_called()

    def test_empty_approved_serve_restored_and_actual_listeners_checked(self):
        empty = ({}, TAIL, "node.example.ts.net", TAIL_PID)
        with patch.object(guard, "root_only"), patch.object(guard, "tailnet_lock", return_value=nullcontext()), patch.object(guard, "tailnet_state", return_value=empty), patch.object(guard, "tailnet_sockets") as sockets, patch.object(guard, "check_tailnet") as check, patch.object(boundary, "command", return_value="{}") as command:
            guard.ensure_tailnet(self.project)
        self.assertTrue(any("--https=443" in call.args for call in command.call_args_list))
        self.assertFalse(any("reset" in call.args for call in command.call_args_list))
        sockets.assert_called_once()
        check.assert_called_once()

    def test_existing_serve_missing_listener_retried_without_rewriting_or_resetting(self):
        valid = (SERVE, TAIL, "node.example.ts.net", TAIL_PID)
        with patch.object(guard, "root_only"), patch.object(guard, "tailnet_lock", return_value=nullcontext()), patch.object(guard, "tailnet_state", return_value=valid), patch.object(guard, "tailnet_sockets"), patch.object(guard, "check_tailnet", side_effect=[boundary.NotReady("listener absent"), None]), patch.object(guard.time, "sleep"), patch.object(boundary, "command") as command:
            guard.ensure_tailnet(self.project)
        command.assert_not_called()

    def test_serve_concurrent_change_is_not_overwritten(self):
        with patch.object(guard, "root_only"), patch.object(guard, "tailnet_lock", return_value=nullcontext()), patch.object(guard, "tailnet_state", return_value=({}, TAIL, "node.example.ts.net", TAIL_PID)), patch.object(guard, "tailnet_sockets"), patch.object(boundary, "command", return_value=json.dumps({"AllowFunnel": {"x": True}})) as command, self.assertRaises(ValueError):
            guard.ensure_tailnet(self.project)
        self.assertFalse(any("--https=443" in call.args for call in command.call_args_list))

    def test_tailnet_check_does_not_depend_on_public_container(self):
        with patch.object(guard, "tailnet_state", return_value=(SERVE, TAIL, "node.example.ts.net", TAIL_PID)), patch.object(guard, "tailnet_sockets"), patch.object(guard, "tailnet_https"), patch.object(boundary, "inspect_proxy") as inspect:
            guard.check_tailnet(self.project)
        inspect.assert_not_called()

    def test_transient_retry_is_bounded_and_unsafe_state_is_not_retried(self):
        with patch.object(guard.time, "monotonic", side_effect=[0, 0, 1]), patch.object(guard.time, "sleep") as sleep, self.assertRaises(boundary.NotReady):
            guard.retry(lambda: (_ for _ in ()).throw(boundary.NotReady("offline")), timeout=1)
        sleep.assert_called_once_with(1)
        with patch.object(guard.time, "sleep") as sleep, self.assertRaises(boundary.UnsafeState):
            guard.retry(lambda: (_ for _ in ()).throw(boundary.UnsafeState("foreign owner")))
        sleep.assert_not_called()

    def test_public_service_and_periodic_tail_guard_have_bounded_independent_dependencies(self):
        public = (ROOT / "systemd/sentinel-runtime-guard.service").read_text()
        self.assertNotIn("tailscale", public)
        self.assertNotIn("network-online", public)
        self.assertIn("TimeoutStartSec=120", public)
        private = (ROOT / "systemd/sentinel-tailscale-guard.service").read_text()
        self.assertNotIn("docker.service", private)
        self.assertIn("tailscale-sentinel-guard ensure", private)
        for name in ("sentinel-runtime-guard.timer", "sentinel-tailscale-guard.timer"):
            self.assertIn("OnUnitInactiveSec=60s", (ROOT / "systemd" / name).read_text())


class ContainerStartupTests(unittest.TestCase):
    setUp = RuntimeGuardTests.setUp
    tearDown = RuntimeGuardTests.tearDown
    def startup(self, *, ready_after=0, arguments=("nginx", "-g", "daemon off;"), public_address=PUBLIC[0], physical_name="eth0", tailnet_name="tailscale0", assigned_only_tailnet=False):
        if public_address != PUBLIC[0] or tailnet_name != "tailscale0":
            module = security_checks.renderer()
            env = {**self.env, "PUBLIC_LISTEN_ADDR": public_address, "TAILSCALE_INTERFACE": tailnet_name}
            self.files = module.rendered_files(public_address, str(self.project), module.parse_default_tls(env), self.sites, env)
            module.write_rendered_files(self.project / "nginx/generated", self.files)
            self.current = (self.project / "nginx/generated/current").resolve()
        bin_dir = self.project / "fake-bin"
        bin_dir.mkdir(exist_ok=True)
        log = self.project / "startup-log"
        counter = self.project / "ip-counter"
        address_interface = tailnet_name if assigned_only_tailnet else physical_name
        scripts = {
            "ip": f'''#!/bin/sh
count=0
[ ! -f "{counter}" ] || read -r count < "{counter}"
count=$((count + 1))
printf '%s\\n' "$count" > "{counter}"
if [ "$count" -gt {ready_after} ]; then printf '2: {address_interface} inet {public_address}/24 scope global {address_interface}\\n'; fi
''',
            "sleep": "#!/bin/sh\nexit 0\n",
            "nginx": f"#!/bin/sh\nprintf 'syntax %s\\n' \"$*\" >> '{log}'\n",
            "official": f"#!/bin/sh\nprintf 'exec %s\\n' \"$*\" >> '{log}'\n",
        }
        for name, content in scripts.items():
            path = bin_dir / name
            path.write_text(content)
            path.chmod(0o755)
        hook = (ROOT / "scripts/container-startup-check.sh").read_text()
        def paths(text):
            return text.replace("/etc/nginx/conf.d", str(self.project / "nginx/generated")).replace("/etc/nginx", str(self.project / "nginx"))
        hook = paths(hook).replace("/docker-entrypoint.sh", str(bin_dir / "official"))
        script = self.project / "entrypoint.sh"
        script.write_text(hook)
        (self.current / ".startup-checksums").write_text(paths(self.files[".startup-checksums"]))
        result = subprocess.run(["sh", str(script), *arguments], env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}, capture_output=True, text=True, timeout=10)
        return result, log.read_text() if log.exists() else "", int(counter.read_text()) if counter.exists() else 0

    def test_startup_waits_for_delayed_address_and_preserves_foreground_arguments(self):
        result, log, polls = self.startup(ready_after=12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreater(polls, 12)
        self.assertIn("exec nginx -g daemon off;", log)

    def test_startup_timeout_is_finite_and_never_uses_wildcards(self):
        result, log, polls = self.startup(ready_after=100)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(polls, 60)
        self.assertNotIn("exec ", log)

    def test_other_servers_boot_with_their_own_public_ipv4_and_interface(self):
        for public, physical, tailnet in (("198.51.100.24", "ens18", "tailscale0"), ("192.0.2.81", "enp5s0", "ts-vpn0"), ("203.0.113.99", "bond0.7", "tailnet0"), ("198.51.100.60", "tailscale-wan", "tailscale0")):
            with self.subTest(server=public):
                result, log, polls = self.startup(public_address=public, physical_name=physical, tailnet_name=tailnet)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("exec nginx -g daemon off;", log)

    def test_custom_tailnet_address_is_never_promoted_to_public_during_boot(self):
        result, log, polls = self.startup(public_address=TAIL[0], tailnet_name="ts-vpn0", assigned_only_tailnet=True)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(polls, 60)
        self.assertNotIn("exec ", log)

    def test_tampered_or_unlisted_config_rejected_before_starting(self):
        (self.current / "10-app.conf").write_text("server { listen 443; }")
        result, log, polls = self.startup()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(polls, 0)
        self.assertNotIn("exec ", log)
        (self.current / "10-app.conf").write_text(self.files["10-app.conf"])
        (self.current / "99-extra.conf").write_text("server { listen [::]:443; }")
        result, log, polls = self.startup()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(polls, 0)

    def test_nginx_validation_command_does_not_wait_or_require_active_revision(self):
        (self.current / "10-app.conf").write_text("not a startup revision")
        result, log, polls = self.startup(arguments=("nginx", "-t"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(polls, 0)
        self.assertIn("exec nginx -t", log)


if __name__ == "__main__":
    unittest.main()
