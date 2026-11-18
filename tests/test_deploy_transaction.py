from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import test_render_sites as fixtures

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_proxy
from security_checks import renderer


class DeployTransactionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RenderSitesTests()
        self.fixture.setUp()
        self.project = self.fixture.root
        (self.project / "nginx").mkdir()
        (self.project / "nginx/nginx.conf").write_text((ROOT / "nginx/nginx.conf").read_text())
        (self.project / "compose.yaml").write_text((ROOT / "compose.yaml").read_text())
        self.output = self.project / "nginx/generated"
        module = renderer()
        env = module.parse_env(self.fixture.env)
        files = module.rendered_files(module.parse_public_address(env), str(self.project), module.parse_default_tls(env), module.load_sites(self.fixture.sites), env)
        module.write_rendered_files(self.output, files)
        self.previous = (self.output / "current").resolve()
        self.commands = []

    def tearDown(self):
        self.fixture.tearDown()

    def run_docker(self, command, **kwargs):
        self.commands.append(list(command))
        if command[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(command, 0, json.dumps([{"Config": {"Image": "nginx:previous@sha256:example"}, "Mounts": [{"Type": "bind", "Source": "/old/cloudflare-realip.conf", "Destination": "/etc/nginx/cloudflare-realip.conf", "RW": False}]}]), "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def patches(self, run=None):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(deploy_proxy, "check_upstreams"))
        stack.enter_context(patch.object(deploy_proxy, "check_certificates"))
        stack.enter_context(patch.object(deploy_proxy, "preflight"))
        stack.enter_context(patch.object(deploy_proxy, "check_public"))
        stack.enter_context(patch.object(deploy_proxy, "install_startup_hook"))
        stack.enter_context(patch.object(deploy_proxy.subprocess, "run", side_effect=run or self.run_docker))
        stack.enter_context(patch.object(deploy_proxy.subprocess, "check_output", return_value=(self.project / "nginx/nginx.conf").read_text()))
        return stack

    def test_candidate_syntax_failure_does_not_activate(self):
        def reject(command, **kwargs):
            self.commands.append(list(command))
            if "run" in command:
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, 0)
        with self.patches(reject), self.assertRaises(subprocess.CalledProcessError):
            deploy_proxy.deploy(self.project)
        self.assertEqual((self.output / "current").resolve(), self.previous)
        self.assertFalse(any("up" in command for command in self.commands))

    def test_failed_running_digest_restores_pointer_image_and_persistent_mount(self):
        with self.patches(), patch.object(deploy_proxy, "wait_revision", side_effect=[ValueError("wrong running digest"), None]), self.assertRaises(ValueError):
            deploy_proxy.deploy(self.project)
        self.assertEqual((self.output / "current").resolve(), self.previous)
        overrides = list((self.output / ".rollback").glob("*-compose.json"))
        self.assertEqual(len(overrides), 1)
        saved = json.loads(overrides[0].read_text())["services"]["proxy"]
        self.assertEqual(saved["image"], "nginx:previous@sha256:example")
        source = next(volume.split(":")[0] for volume in saved["volumes"] if isinstance(volume, str))
        self.assertTrue(any(isinstance(volume, dict) and volume["target"] == "/etc/nginx/cloudflare-realip.conf" for volume in saved["volumes"]))
        self.assertTrue(Path(source).is_file())
        self.assertIn(str(self.output / ".rollback"), source)
        self.assertTrue(any(str(overrides[0]) in command and "up" in command for command in self.commands))

    def test_check_only_does_not_activate_or_reload(self):
        with self.patches():
            deploy_proxy.deploy(self.project, check_only=True)
        self.assertEqual((self.output / "current").resolve(), self.previous)
        self.assertFalse(any("up" in command or "reload" in command for command in self.commands))

    def test_success_explicitly_reloads_and_checks_running_digest(self):
        with self.patches(), patch.object(deploy_proxy, "wait_revision") as health:
            deploy_proxy.deploy(self.project)
        self.assertNotEqual((self.output / "current").resolve(), self.previous)
        self.assertTrue(self.previous.is_dir())
        self.assertTrue(any("reload" in command for command in self.commands))
        health.assert_called_once_with((self.output / "current").resolve())

    def test_conflict_appearing_during_validation_aborts_without_recreating_or_rollback(self):
        with self.patches(), patch.object(deploy_proxy, "preflight", side_effect=[None, ValueError("new conflicting owner")]), self.assertRaises(ValueError):
            deploy_proxy.deploy(self.project)
        self.assertEqual((self.output / "current").resolve(), self.previous)
        self.assertFalse(any("up" in command or "restart" in command or "reload" in command for command in self.commands))

    def test_check_only_uses_existing_candidate_hook_without_installing_root_snapshot(self):
        with self.patches(), patch.object(deploy_proxy, "install_startup_hook") as install:
            deploy_proxy.deploy(self.project, check_only=True)
        install.assert_not_called()
        validation = next(command for command in self.commands if "run" in command)
        self.assertIn("--entrypoint", validation)
        self.assertIn("nginx", validation)
        self.assertIn(f"{self.project / 'scripts/container-startup-check.sh'}:/usr/local/bin/sentinel-entrypoint:ro", validation)


if __name__ == "__main__":
    unittest.main()
