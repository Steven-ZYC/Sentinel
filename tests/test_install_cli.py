import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import configure
import listener_boundary as boundary
import security_checks


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name)
        for name in (".env.example", "sites.example.json"):
            shutil.copy(ROOT / name, self.project)

    def prepare(self, mode, proxy=()):
        answers = ["192.0.2.8", "", mode, *proxy, "portal.example.com", "", "", "", ""]
        with patch("builtins.input", side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
            configure.configure(self.project)

    def test_first_install_modes_and_repeat(self):
        for mode, proxy in (("cloudflare", []), ("direct", []), ("trusted-proxy", ["10.0.0.0/24", "X-Real-IP"])):
            with self.subTest(mode=mode):
                self.prepare(mode, proxy)
                env = security_checks.renderer().parse_env(self.project / ".env")
                self.assertEqual(security_checks.renderer().edge_policy(env)[0], mode)
                manifest = json.loads((self.project / "sites.json").read_text())
                self.assertEqual(manifest["sites"][0]["upstream"]["port"], 10443)
                with patch("builtins.input", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
                    configure.configure(self.project)
                for filename in (".env", "sites.json"):
                    path = self.project / filename
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    path.unlink()

    def test_invalid_policy_leaves_no_config(self):
        with self.assertRaises(ValueError):
            self.prepare("trusted-proxy", ["0.0.0.0/0", "X-Real-IP"])
        self.assertFalse((self.project / ".env").exists())
        self.assertFalse((self.project / "sites.json").exists())

    def test_missing_legacy_mode_cannot_publish_direct(self):
        with self.assertRaisesRegex(ValueError, "EDGE_MODE"):
            security_checks.renderer().edge_policy({"PUBLIC_LISTEN_ADDR": "192.0.2.8"})

    def test_partial_config_preserved(self):
        path = self.project / ".env"
        path.write_text("existing")
        with self.assertRaises(ValueError):
            configure.configure(self.project)
        self.assertEqual(path.read_text(), "existing")

    def test_all_upstream_socket_owners_must_belong_to_safeline(self):
        self.prepare("direct")
        with patch.dict(os.environ, {"SAFELINE_CONTAINER": "test-tengine"}), \
             patch.object(security_checks, "run", return_value="a"*64) as inspect, \
             patch.object(boundary, "owned_by_proxy", side_effect=lambda pid, _: pid == 7), \
             patch.object(boundary, "listeners") as listeners:
            for pids in ([7], [7, 8], []):
                listeners.return_value = [boundary.Listener("127.0.0.1:10443", frozenset(pids), "listener")]
                if pids == [7]:
                    security_checks.check_upstreams(self.project)
                else:
                    with self.assertRaises(boundary.UnsafeState):
                        security_checks.check_upstreams(self.project)
            self.assertEqual(inspect.call_args.args[-1], "test-tengine")
