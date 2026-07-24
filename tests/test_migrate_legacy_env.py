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
MIGRATOR = ROOT / "scripts" / "migrate-legacy-env.py"


class MigrateLegacyEnvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.env = self.root / ".env"
        self.output = self.root / "sites.json"
        self.env.write_text(
            "\n".join(
                (
                    "DOMAIN=app.example.com",
                    "UPSTREAM_ADDR=127.0.0.1",
                    "UPSTREAM_PORT=10443",
                    "UPSTREAM_SCHEME=http",
                    "GBA_DOMAIN=portal.example.com",
                    "GBA_UPSTREAM_ADDR=127.0.0.1",
                    "GBA_UPSTREAM_PORT=10444",
                    "TLS_CERT_PATH=/certs/fullchain.pem",
                    "TLS_KEY_PATH=/certs/privkey.pem",
                    "CONTENT_SECURITY_POLICY=default-src 'self'",
                    "PERMISSIONS_POLICY=camera=()",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def migrate(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(MIGRATOR),
                "--env",
                str(self.env),
                "--output",
                str(self.output),
                *arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_writes_proxy_sites_and_requested_redirect(self) -> None:
        result = self.migrate("--write", "--redirect", "legacy.example.com=https://app.example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], 1)
        self.assertEqual([site["domain"] for site in manifest["sites"]], ["app.example.com", "portal.example.com", "legacy.example.com"])
        self.assertEqual(manifest["sites"][2]["type"], "redirect")
        self.assertEqual(manifest["sites"][2]["redirect_to"], "https://app.example.com")

    def test_rejects_legacy_https_listener(self) -> None:
        content = self.env.read_text(encoding="utf-8").replace("UPSTREAM_SCHEME=http", "UPSTREAM_SCHEME=https")
        self.env.write_text(content, encoding="utf-8")
        result = self.migrate("--write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UPSTREAM_SCHEME must be http", result.stderr)


if __name__ == "__main__":
    unittest.main()
