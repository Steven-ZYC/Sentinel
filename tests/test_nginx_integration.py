"""Optional real-NGINX tests. Set SENTINEL_TEST_NGINX to a local executable.

Only randomly allocated loopback ports and ephemeral test certificates are used.
No Docker access, root, external DNS, or production configuration is required.
"""
from __future__ import annotations

import contextlib
import http.client
import http.server
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

import test_render_sites as fixtures

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from security_checks import renderer
import verify_edge
import runtime_guard


def reserve_test_port():
    # Avoid the OS ephemeral client range and hold the reservation until startup.
    # Otherwise backend allocation or TIME_WAIT can steal a just-probed port.
    for _ in range(100):
        listener = socket.socket()
        try:
            listener.bind(("127.0.0.1", 15000 + secrets.randbelow(10000)))
            return listener
        except OSError:
            listener.close()
    raise RuntimeError("no free isolated test port")


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Strict-Transport-Security", "max-age=0")
        self.send_header("Set-Cookie", "session=test; Path=/")
        self.end_headers()
        self.wfile.write(json.dumps(dict(self.headers)).encode())

    def log_message(self, *args):
        pass


@unittest.skipUnless(os.environ.get("SENTINEL_TEST_NGINX"), "set SENTINEL_TEST_NGINX for isolated real-NGINX tests")
class NginxIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RenderSitesTests()
        self.fixture.setUp()
        self.root = self.fixture.root
        self.nginx = os.environ["SENTINEL_TEST_NGINX"]
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=app.example.com", "-addext", "subjectAltName=DNS:app.example.com,DNS:legacy.example.com,DNS:localhost", "-keyout", str(self.fixture.key), "-out", str(self.fixture.cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.fixture.key.chmod(0o600)
        self.reservations = [reserve_test_port() for _ in range(3)]
        self.http_port, self.https_port, self.health_port = [listener.getsockname()[1] for listener in self.reservations]
        self.backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        self.thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.thread.start()
        manifest = json.loads(self.fixture.sites.read_text())
        manifest["sites"][0]["upstream"]["port"] = self.backend.server_port
        self.fixture.write_manifest(manifest["sites"])
        self.module = renderer()
        self.env = self.module.parse_env(self.fixture.env)
        self.env["HEALTHCHECK_PORT"] = str(self.health_port)
        self.env["PUBLIC_LISTEN_IPV6"] = "2001:db8::10"
        self.config = self.root / "nginx.conf"
        bootstrap = (ROOT / "nginx/nginx.conf").read_text()
        bootstrap = bootstrap.replace("user nginx;\n", "").replace("worker_processes 2;", "worker_processes 1;")
        bootstrap = bootstrap.replace("pid /var/run/nginx.pid;", f"pid {self.root}/nginx.pid;")
        bootstrap = bootstrap.replace("include /etc/nginx/mime.types;", "")
        bootstrap = bootstrap.replace("/dev/stderr", str(self.root / "error.log")).replace("/dev/stdout", str(self.root / "access.log"))
        bootstrap = bootstrap.replace(f"error_log {self.root}/error.log warn;", f"error_log {self.root}/error.log notice;")
        bootstrap = bootstrap.replace("include /etc/nginx/conf.d/current/*.conf;", f"include {self.fixture.generated}/current/*.conf;")
        bootstrap = bootstrap.replace("    default_type application/octet-stream;", f"    default_type application/octet-stream;\n    client_body_temp_path {self.root}/body;\n    proxy_temp_path {self.root}/proxy;\n    fastcgi_temp_path {self.root}/fastcgi;\n    uwsgi_temp_path {self.root}/uwsgi;\n    scgi_temp_path {self.root}/scgi;")
        self.config.write_text(bootstrap)

    def tearDown(self):
        for listener in self.reservations:
            listener.close()
        self.backend.shutdown()
        self.backend.server_close()
        self.thread.join(timeout=2)
        self.fixture.tearDown()

    def publish(self, mode):
        self.env["EDGE_MODE"] = mode
        self.env["TRUSTED_PROXY_CIDRS"] = "127.0.0.1/32,10.0.0.0/24" if mode == "trusted-proxy" else ""
        sites = self.module.load_sites(self.fixture.sites)
        files = self.module.rendered_files(self.env["PUBLIC_LISTEN_ADDR"], str(self.root), self.module.parse_default_tls(self.env), sites, self.env)
        for name, content in files.items():
            files[name] = content.replace("/etc/sentinel/tls", str(self.root)).replace("203.0.113.10:80", f"127.0.0.1:{self.http_port}").replace("203.0.113.10:443", f"127.0.0.1:{self.https_port}").replace("[2001:db8::10]:80", f"[::1]:{self.http_port}").replace("[2001:db8::10]:443", f"[::1]:{self.https_port}")
        self.module.write_rendered_files(self.fixture.generated, files)

    @contextlib.contextmanager
    def running(self, mode):
        self.publish(mode)
        subprocess.run([self.nginx, "-p", str(self.root), "-c", str(self.config), "-t", "-e", str(self.root / "error.log")], check=True, capture_output=True)
        for listener in self.reservations:
            listener.close()
        process = subprocess.Popen([self.nginx, "-p", str(self.root), "-c", str(self.config), "-g", "daemon off;", "-e", str(self.root / "error.log")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            for _ in range(50):
                if process.poll() is not None:
                    self.fail((self.root / "error.log").read_text())
                try:
                    self.health()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                self.fail("isolated NGINX startup timed out")
            yield process
        finally:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def health(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.health_port, timeout=2)
        try:
            connection.request("GET", "/.sentinel/health")
            response = connection.getresponse()
            data = response.read()
            self.assertEqual(response.status, 200)
            self.assertEqual(data, b"ok\n")
            return response.getheader("X-Sentinel-Config")
        finally:
            connection.close()

    def request(self, headers=None, source="127.0.0.1", method="GET", host="app.example.com"):
        context = ssl.create_default_context(cafile=str(self.fixture.cert))
        connection = http.client.HTTPSConnection("localhost", self.https_port, context=context, source_address=(source, 0), timeout=3)
        try:
            connection.request(method, "/", headers={"Host": host, **(headers or {})})
            response = connection.getresponse()
            body = response.read()
            return response.status, response.getheaders(), body
        finally:
            connection.close()

    def test_direct_ignores_spoofed_headers_and_hides_upstream_hsts(self):
        with self.running("direct"):
            status, headers, body = self.request({"X-Forwarded-For": "198.51.100.99", "CF-Connecting-IP": "198.51.100.99", "Forwarded": "for=198.51.100.99", "True-Client-IP": "198.51.100.99"})
            self.assertEqual(status, 200)
            forwarded = json.loads(body)
            self.assertEqual(forwarded["X-Real-IP"], "127.0.0.1")
            self.assertEqual(forwarded["X-Forwarded-For"], "127.0.0.1")
            self.assertFalse(any(name in forwarded for name in ("CF-Connecting-IP", "Forwarded", "True-Client-IP")))
            self.assertEqual([value for name, value in headers if name.lower() == "strict-transport-security"], ["max-age=31536000"])
            cookie = next(value.lower() for name, value in headers if name.lower() == "set-cookie")
            self.assertTrue(all(value in cookie for value in ("secure", "httponly", "samesite=lax")))
            self.assertEqual(self.request(method="TRACE")[0], 405)
            self.assertEqual(self.request(host="unknown.example.com")[0], 421)
            grouped = {}
            for name, value in headers:
                grouped.setdefault(name.lower(), []).append(value)
            verify_edge.validate_headers([(status, grouped)])

    def test_trusted_proxy_restores_ip_but_blocks_other_socket_peers(self):
        with self.running("trusted-proxy"):
            status, _, body = self.request({"X-Forwarded-For": "198.51.100.9, 10.0.0.8"})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["X-Real-IP"], "198.51.100.9")
            self.assertEqual(self.request({"X-Forwarded-For": "127.0.0.1"}, source="127.0.0.2")[0], 403)
            self.assertEqual(self.request(source="127.0.0.2", host="legacy.example.com")[0], 403)

    def test_cloudflare_peer_acl_and_health_independence(self):
        with self.running("cloudflare"):
            self.assertEqual(self.request({"CF-Connecting-IP": "173.245.48.1"})[0], 403)
            self.assertEqual(self.health(), (self.fixture.output / ".config-digest").read_text().strip())

    def test_verified_tls_baseline_and_explicit_legacy_rejection(self):
        with self.running("direct"):
            verify_edge.assert_tls_result(verify_edge.tls_probe("localhost", self.https_port, "-tls1_2", str(self.fixture.cert)), legacy=False)
            for protocol in ("-tls1", "-tls1_1"):
                verify_edge.assert_tls_result(verify_edge.tls_probe("localhost", self.https_port, protocol, str(self.fixture.cert)), legacy=True)

    def test_runtime_tls_probe_verifies_declared_certificate_on_both_address_families(self):
        with self.running("direct"):
            runtime_guard.public_tls(["127.0.0.1", "[::1]"], self.module.load_sites(self.fixture.sites), port=self.https_port)

    def test_atomic_publish_then_explicit_reload_serves_new_digest(self):
        with self.running("direct") as master:
            old = self.health()
            children = Path(f"/proc/{master.pid}/task/{master.pid}/children")
            old_workers = set(children.read_text().split())
            self.assertTrue(old_workers)
            self.env["EDGE_MODE"] = "cloudflare"
            self.publish("cloudflare")
            new = (self.fixture.output / ".config-digest").read_text().strip()
            self.assertNotEqual(old, new)
            self.assertEqual(self.health(), old)
            subprocess.run([self.nginx, "-p", str(self.root), "-c", str(self.config), "-s", "reload", "-e", str(self.root / "error.log")], check=True)
            # One new-worker response does not mean old workers have exited:
            # the next connection may still hit an old listener. Confirm the
            # original workers are reaped before asserting stable responses.
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if old_workers.isdisjoint(children.read_text().split()) and self.health() == new and self.request()[0] == 403:
                    break
                time.sleep(0.05)
            self.assertTrue(old_workers.isdisjoint(children.read_text().split()), (self.root / "error.log").read_text())
            self.assertEqual(self.health(), new, (self.root / "error.log").read_text())
            self.assertEqual(self.request()[0], 403)


if __name__ == "__main__":
    unittest.main()
