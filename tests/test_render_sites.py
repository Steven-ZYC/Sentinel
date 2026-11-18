# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Steven Zhang

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts" / "render-sites.py"


class RenderSitesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cert = self.root / "fullchain.pem"
        self.key = self.root / "privkey.pem"
        self.cert.write_text("certificate", encoding="utf-8")
        self.key.write_text("private-key", encoding="utf-8")
        self.key.chmod(0o600)
        self.env = self.root / ".env"
        self.env.write_text(
            "\n".join(
                (
                    "PUBLIC_LISTEN_ADDR=203.0.113.10",
                    "EDGE_MODE=direct",
                    f"TLS_MOUNT_ROOT={self.root}",
                    f"DEFAULT_TLS_CERT_PATH={self.cert}",
                    f"DEFAULT_TLS_KEY_PATH={self.key}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self.sites = self.root / "sites.json"
        self.generated = self.root / "generated"
        self.output = self.generated / "current"
        self.write_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self, sites: list[dict[str, object]] | None = None) -> None:
        if sites is None:
            sites = [
                {
                    "name": "app",
                    "type": "proxy",
                    "domain": "app.example.com",
                    "certificate": str(self.cert),
                    "private_key": str(self.key),
                    "upstream": {"address": "127.0.0.1", "port": 10443, "scheme": "http"},
                    "security": {
                        "content_security_policy": "default-src 'self'",
                        "permissions_policy": "camera=()",
                    },
                },
                {
                    "name": "legacy",
                    "type": "redirect",
                    "domain": "legacy.example.com",
                    "certificate": str(self.cert),
                    "private_key": str(self.key),
                    "redirect_to": "https://app.example.com",
                },
            ]
        self.sites.write_text(json.dumps({"version": 1, "sites": sites}), encoding="utf-8")

    def render(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(RENDERER),
                "--env",
                str(self.env),
                "--sites",
                str(self.sites),
                "--output",
                str(self.generated),
                *arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_renders_proxy_redirect_and_default_servers(self) -> None:
        result = self.render("--check-certificates")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("default_server", (self.output / "02-default.conf").read_text(encoding="utf-8"))
        proxy = (self.output / "10-app.conf").read_text(encoding="utf-8")
        self.assertIn("server 127.0.0.1:10443", proxy)
        self.assertIn("ssl_certificate \"/etc/sentinel/tls/fullchain.pem\"", proxy)
        self.assertIn("server_name app.example.com", proxy)
        redirect = (self.output / "11-legacy.conf").read_text(encoding="utf-8")
        self.assertIn("return 308 https://app.example.com$request_uri", redirect)
        self.assertEqual((self.output / ".healthcheck-host").read_text(encoding="utf-8"), "app.example.com\n")
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o644, path)
        checked = self.render("--check", "--check-certificates")
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_rejects_shared_safeline_port(self) -> None:
        first = json.loads(self.sites.read_text(encoding="utf-8"))["sites"][0]
        second = dict(first)
        second["name"] = "another"
        second["domain"] = "another.example.com"
        self.write_manifest([first, second])
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct SafeLine listener port", result.stderr)

    def test_rejects_non_loopback_upstream(self) -> None:
        manifest = json.loads(self.sites.read_text(encoding="utf-8"))
        manifest["sites"][0]["upstream"]["address"] = "10.0.0.8"
        self.write_manifest(manifest["sites"])
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be 127.0.0.1", result.stderr)

    def test_rejects_certificate_outside_tls_mount_root(self) -> None:
        external = self.root.with_name(f"{self.root.name}-outside.pem")
        self.addCleanup(external.unlink, missing_ok=True)
        external.write_text("external", encoding="utf-8")
        manifest = json.loads(self.sites.read_text(encoding="utf-8"))
        manifest["sites"][0]["certificate"] = str(external)
        self.write_manifest(manifest["sites"])
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be inside TLS_MOUNT_ROOT", result.stderr)

    def test_check_detects_stale_generated_file(self) -> None:
        self.assertEqual(self.render().returncode, 0)
        (self.output / "10-app.conf").write_text("stale", encoding="utf-8")
        result = self.render("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("out of date", result.stderr)


if __name__ == "__main__":
    unittest.main()
