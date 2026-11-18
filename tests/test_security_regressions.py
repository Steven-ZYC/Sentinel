from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import test_render_sites as fixtures

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import security_checks
import safeline_listener
import verify_edge
import network_boundary
import harden_deployment


class ConfigurationSecurityTests(fixtures.RenderSitesTests):
    def add_env(self, values: str):
        with self.env.open("a") as stream:
            stream.write(values + "\n")

    def test_direct_does_not_trust_claimed_client_headers(self):
        self.assertEqual(self.render().returncode, 0)
        policy = (self.output / "00-edge.conf").read_text()
        self.assertNotIn("set_real_ip_from", policy)
        self.assertIn("default 1", policy)
        proxy = (self.output / "10-app.conf").read_text()
        for header in ("CF-Connecting-IP", "Forwarded", "True-Client-IP"):
            self.assertIn(f'proxy_set_header {header} "";', proxy)
        self.assertIn("proxy_hide_header Strict-Transport-Security", proxy)

    def test_cloudflare_has_peer_acl_independent_of_claimed_ip(self):
        self.add_env("EDGE_MODE=cloudflare")
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = (self.output / "00-edge.conf").read_text()
        self.assertIn("geo $realip_remote_addr", policy)
        self.assertIn("default 0", policy)
        self.assertIn("real_ip_header CF-Connecting-IP", policy)
        for file in ("10-app.conf", "11-legacy.conf"):
            self.assertEqual((self.output / file).read_text().count("if ($sentinel_peer_allowed = 0)"), 2)

    def test_trusted_proxy_requires_explicit_non_universal_networks(self):
        for cidrs in ("", "0.0.0.0/0", "::/0", "10.0.0.1/24", "10.0.0.0/8; return 200"):
            with self.subTest(cidrs=cidrs):
                self.add_env(f"EDGE_MODE=trusted-proxy\nTRUSTED_PROXY_CIDRS={cidrs}")
                self.assertNotEqual(self.render().returncode, 0)
        self.add_env("TRUSTED_PROXY_CIDRS=10.0.0.0/24,2001:db8::/32")
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("real_ip_recursive on", (self.output / "00-edge.conf").read_text())

    def test_ipv6_requires_explicit_address(self):
        self.add_env("PUBLIC_LISTEN_IPV6=::")
        self.assertNotEqual(self.render().returncode, 0)
        self.add_env("PUBLIC_LISTEN_IPV6=2001:db8::10")
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("listen [2001:db8::10]:443 ssl", (self.output / "10-app.conf").read_text())

    def test_private_key_and_directory_permissions_fail_closed(self):
        self.key.chmod(0o644)
        self.assertNotEqual(self.render("--check-certificates").returncode, 0)
        self.key.chmod(0o600)
        self.root.chmod(0o777)
        self.assertNotEqual(self.render("--check-certificates").returncode, 0)
        self.root.chmod(0o700)

    def test_certificate_dollar_expansion_rejected(self):
        manifest = json.loads(self.sites.read_text())
        manifest["sites"][0]["private_key"] = str(self.root / "$host.pem")
        self.write_manifest(manifest["sites"])
        self.assertNotEqual(self.render().returncode, 0)

    def test_ssh_port_cannot_be_selected_as_business_upstream(self):
        manifest = json.loads(self.sites.read_text())
        manifest["sites"][0]["upstream"]["port"] = 22
        self.write_manifest(manifest["sites"])
        self.assertNotEqual(self.render().returncode, 0)

    def test_backup_archival_is_private_and_outside_webroot(self):
        webroot = self.root / "public"
        webroot.mkdir()
        backup = webroot / "index.html.pre-split-20260101T000000Z"
        backup.write_text("legacy page")
        destination = harden_deployment.archive_backups(webroot, self.root / "private")
        self.assertFalse(backup.exists())
        private = destination / backup.name
        self.assertEqual(private.read_text(), "legacy page")
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            harden_deployment.archive_backups(webroot, webroot / "backups")

    def test_backup_symlink_rejected_before_moving_other_files(self):
        webroot = self.root / "public"
        webroot.mkdir()
        ordinary = webroot / "index.html.pre-split-old"
        ordinary.write_text("old")
        (webroot / "index.html.pre-split-link").symlink_to(self.key)
        with self.assertRaises(ValueError):
            harden_deployment.archive_backups(webroot, self.root / "private")
        self.assertTrue(ordinary.exists())

    def test_stage_failure_preserves_whole_old_revision(self):
        self.assertEqual(self.render().returncode, 0)
        previous = os.readlink(self.output)
        old_content = {path.name: path.read_text() for path in self.output.iterdir()}
        module = security_checks.renderer()
        with patch.object(module.os, "fsync", side_effect=OSError("simulated storage failure")):
            with self.assertRaises(OSError):
                module.write_rendered_files(self.generated, {"new.conf": "new configuration"})
        self.assertEqual(os.readlink(self.output), previous)
        self.assertEqual({path.name: path.read_text() for path in self.output.iterdir()}, old_content)
        self.assertEqual(self.render("--check").returncode, 0)

    def test_staging_does_not_activate_and_legacy_files_not_deleted(self):
        self.assertEqual(self.render().returncode, 0)
        previous = os.readlink(self.output)
        legacy = self.generated / "old.conf"
        legacy.write_text("retained for migration rollback")
        staged = self.render("--stage")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertEqual(os.readlink(self.output), previous)
        self.assertTrue((Path(staged.stdout.strip()) / "10-app.conf").is_file())
        self.assertTrue(legacy.is_file())

    def test_healthcheck_independent_of_public_tls_and_port_collision(self):
        self.assertEqual(self.render().returncode, 0)
        health = (self.output / "01-healthcheck.conf").read_text()
        self.assertIn("listen 127.0.0.1:18090", health)
        self.assertNotIn("ssl", health)
        self.assertNotIn("sentinel_peer_allowed", health)
        self.assertIn((self.output / ".config-digest").read_text().strip(), health)
        self.add_env("HEALTHCHECK_PORT=10443")
        self.assertNotEqual(self.render().returncode, 0)

    def test_firewall_policy_is_scoped_and_preserves_ssh(self):
        module = security_checks.renderer()
        sites = module.load_sites(self.sites)
        for mode in ("direct", "cloudflare", "trusted-proxy"):
            env = {"PUBLIC_LISTEN_ADDR": "203.0.113.10", "PUBLIC_INTERFACE": "ens3", "EDGE_MODE": mode, "TRUSTED_PROXY_CIDRS": "10.0.0.0/24" if mode == "trusted-proxy" else ""}
            commands = network_boundary.firewall_rules(env, sites)
            self.assertTrue(all("ens3" in command for command in commands))
            self.assertFalse(any("22" in command or "reset" in command for command in commands))
            if mode != "direct":
                self.assertEqual(commands[-1][0], "deny")


class RuntimeSecurityTests(unittest.TestCase):
    def test_all_active_sockets_checked_not_just_one_loopback(self):
        for additional in ("[::]:10443", "0.0.0.0:10443", "203.0.113.10:10443", "10.1.1.1:10443"):
            with self.subTest(additional=additional), self.assertRaises(ValueError):
                security_checks.assert_loopback(10443, {"127.0.0.1:10443", additional})
        security_checks.assert_loopback(10443, {"127.0.0.1:10443", "[::1]:10443"})

    def test_listener_rewrites_dual_stack_and_non_default_bindings(self):
        original = "server {\n listen 0.0.0.0:10443;\n listen [::]:10443 ipv6only=on;\n listen 10.0.0.2:10444;\n}\n"
        result = safeline_listener.rewrite(original, 10443)
        self.assertIn("listen 127.0.0.1:10443;", result)
        self.assertIn("listen [::1]:10443 ipv6only=on;", result)
        self.assertIn("listen 10.0.0.2:10444;", result)
        self.assertNotIn("[::]:10443", result)

    def test_serve_rejects_funnel_additional_routes_and_forwards(self):
        valid = {"TCP": {"443": {"HTTPS": True}}, "Web": {"node.example.ts.net:443": {"Handlers": {"/": {"Proxy": "https+insecure://localhost:9443"}}}}}
        security_checks.assert_serve(valid)
        for extra in ({"AllowFunnel": {"node.example.ts.net:443": True}}, {"Foreground": {"session": {"AllowFunnel": {"x": True}}}}):
            with self.assertRaises(ValueError):
                security_checks.assert_serve({**valid, **extra})
        invalid = json.loads(json.dumps(valid))
        invalid["TCP"]["8080"] = {"TCPForward": "127.0.0.1:10443"}
        with self.assertRaises(ValueError):
            security_checks.assert_serve(invalid)
        invalid = json.loads(json.dumps(valid))
        invalid["Web"]["node.example.ts.net:443"]["Handlers"]["/public"] = {"Proxy": "http://localhost:10443"}
        with self.assertRaises(ValueError):
            security_checks.assert_serve(invalid)

    def headers(self):
        return {
            "strict-transport-security": ["max-age=31536000"],
            "content-security-policy": ["default-src 'self'"],
            "x-content-type-options": ["nosniff"], "x-frame-options": ["DENY"],
            "referrer-policy": ["strict-origin-when-cross-origin"],
            "permissions-policy": ["camera=()"],
            "cross-origin-opener-policy": ["same-origin"],
            "cross-origin-resource-policy": ["same-origin"],
        }

    def test_hsts_zero_duplicate_headers_and_final_error_fail(self):
        verify_edge.validate_headers([(200, self.headers())])
        for values in (["max-age=0"], ["max-age=31536000", "max-age=0"], []):
            headers = self.headers()
            headers["strict-transport-security"] = values
            with self.assertRaises(ValueError):
                verify_edge.validate_headers([(200, headers)])
        with self.assertRaises(ValueError):
            verify_edge.validate_headers([(308, self.headers()), (200, {})])
        with self.assertRaises(ValueError):
            verify_edge.validate_headers([(502, self.headers())])

    def test_insecure_cookies_rejected(self):
        headers = self.headers()
        headers["set-cookie"] = ["session=redacted; Secure; SameSite=Lax"]
        with self.assertRaises(ValueError):
            verify_edge.validate_headers([(200, headers)])

    def test_network_failure_is_not_legacy_tls_rejection(self):
        failed = subprocess.CompletedProcess([], 1, "", "connect:errno=111")
        with self.assertRaises(ValueError):
            verify_edge.assert_tls_result(failed, legacy=True)
        rejected = subprocess.CompletedProcess([], 1, "", "tlsv1 alert protocol version")
        verify_edge.assert_tls_result(rejected, legacy=True)
        with self.assertRaises(ValueError):
            verify_edge.assert_tls_result(failed, legacy=False)

    def test_duplicate_firewall_rule_is_reordered_without_touching_ssh(self):
        command = ["ufw", "insert", "1", "deny", "in", "on", "ens3", "proto", "tcp", "to", "any", "port", "80,443", "comment", "Sentinel other peers"]
        duplicate = subprocess.CompletedProcess(command, 0, "Skipping inserting existing rule\n", "")
        success = subprocess.CompletedProcess(command, 0, "Rule inserted\n", "")
        with patch.object(network_boundary.subprocess, "run", side_effect=[duplicate, success, success]) as run:
            network_boundary.apply_command(command)
        delete = run.call_args_list[1].args[0]
        self.assertEqual(delete, ["ufw", "--force", "delete", *command[3:-2]])
        self.assertNotIn("22", delete)
        self.assertEqual(run.call_args_list[2].args[0], command)


if __name__ == "__main__":
    unittest.main()
